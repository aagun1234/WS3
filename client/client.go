package client

import (
	"context"
	"encoding/binary" // New import for binary operations
	"fmt"
	"io"
	"log"
	"net"
	"strconv" // New import for strconv.Atoi
	"sync"
	"time"
	"github.com/aagun1234/ws3/config"
	"github.com/aagun1234/ws3/protocol"
	//"golang.org/x/net/proxy"
)

// Client is the A-side (TCP/SOCKS5 proxy)
type Client struct {
	cfg           *config.Config
	listener      net.Listener
	tunnelManager *TunnelManager
	sessions      *sync.Map // map[uint64]*Session
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewClient creates a new Client instance.
func NewClient(cfg *config.Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	sessions := &sync.Map{} // Initialize the shared sessions map
	tm := NewTunnelManager(cfg, sessions)

	return &Client{
		cfg:           cfg,
		tunnelManager: tm,
		sessions:      sessions,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start runs the client proxy server (TCP or SOCKS5).
func (c *Client) Start() error {
	var err error
	c.listener, err = net.Listen("tcp", c.cfg.ClientListenAddr) // Listen on TCP regardless of proxy mode
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", c.cfg.ClientListenAddr, err)
	}

	if c.cfg.ClientProxyMode == "socks5" {
		log.Printf("SOCKS5 proxy listening on %s, forwarding via tunnel.", c.cfg.ClientListenAddr)
		go c.listenForSOCKS5Connections()
	} else { // Default to TCP
		log.Printf("TCP proxy listening on %s, forwarding to server for target: %s", c.cfg.ClientListenAddr, c.cfg.ForwardTarget)
		go c.listenForTCPConnections()
	}


	// Keep main goroutine alive until context is cancelled
	<-c.ctx.Done()
	log.Println("Client stopped.")
	return nil
}

// listenForSOCKS5Connections accepts incoming SOCKS5 connections.
func (c *Client) listenForSOCKS5Connections() {
	defer func() {
		if c.listener != nil {
			c.listener.Close()
		}
		c.tunnelManager.Shutdown()
		log.Println("SOCKS5 listener goroutine exited.")
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			if tcpListener, ok := c.listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(time.Second))
			}
			conn, err := c.listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Error accepting SOCKS5 connection: %v", err)
				continue
			}
			go c.handleSOCKS5Connection(conn)
		}
	}
}

// handleSOCKS5Connection performs SOCKS5 handshake and sets up tunneling.
func (c *Client) handleSOCKS5Connection(clientConn net.Conn) {
	defer clientConn.Close()

	if c.cfg.LogDebug>=2 {
		log.Printf("Handling new SOCKS5 connection from %s", clientConn.RemoteAddr())
	}


	// SOCKS5 Protocol Handshake (RFC 1928)
	// 1. Read VER, NMETHODS, METHODS
	buf := make([]byte, 258) // Max size: 1 (VER) + 1 (NMETHODS) + 255 (METHODS)
	n, err := io.ReadFull(clientConn, buf[:2])
	if err != nil || n != 2 || buf[0] != 0x05 {
		log.Printf("SOCKS5 handshake (read VER/NMETHODS) failed for %s: %v", clientConn.RemoteAddr(), err)
		return
	}
	nmethods := int(buf[1])
	n, err = io.ReadFull(clientConn, buf[:nmethods])
	if err != nil || n != nmethods {
		log.Printf("SOCKS5 handshake (read METHODS) failed for %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	// 2. Respond with VER, METHOD (only support No Authentication Required - 0x00)
	_, err = clientConn.Write([]byte{0x05, 0x00}) // SOCKS5, No Auth Required
	if err != nil {
		log.Printf("SOCKS5 handshake (write METHOD) failed for %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	// 3. Read VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	// CMD: 0x01 (CONNECT), 0x02 (BIND), 0x03 (UDP ASSOCIATE) - we only support CONNECT
	// ATYP: 0x01 (IPv4), 0x03 (Domain Name), 0x04 (IPv6)
	n, err = io.ReadFull(clientConn, buf[:4]) // VER, CMD, RSV, ATYP
	if err != nil || n != 4 || buf[0] != 0x05 || buf[2] != 0x00 { // VER=5, RSV=0x00
		log.Printf("SOCKS5 request (read VER/CMD/RSV/ATYP) failed for %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 0x01 { // Only support CONNECT command
		log.Printf("SOCKS5 request from %s: Unsupported CMD: 0x%x", clientConn.RemoteAddr(), cmd)
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Command not supported
		return
	}

	var targetAddr string
	switch atyp {
	case 0x01: // IPv4
		n, err = io.ReadFull(clientConn, buf[:4])
		if err != nil || n != 4 {
			log.Printf("SOCKS5 request from %s: Failed to read IPv4 address: %v", clientConn.RemoteAddr(), err)
			return
		}
		ip := net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
		n, err = io.ReadFull(clientConn, buf[:2]) // Port
		if err != nil || n != 2 {
			log.Printf("SOCKS5 request from %s: Failed to read port for IPv4: %v", clientConn.RemoteAddr(), err)
			return
		}
		port := binary.BigEndian.Uint16(buf[:2])
		targetAddr = net.JoinHostPort(ip, strconv.Itoa(int(port)))
	case 0x03: // Domain Name
		n, err = io.ReadFull(clientConn, buf[:1]) // Read length of domain name
		if err != nil || n != 1 {
			log.Printf("SOCKS5 request from %s: Failed to read domain name length: %v", clientConn.RemoteAddr(), err)
			return
		}
		domainLen := int(buf[0])
		n, err = io.ReadFull(clientConn, buf[:domainLen]) // Read domain name
		if err != nil || n != domainLen {
			log.Printf("SOCKS5 request from %s: Failed to read domain name: %v", clientConn.RemoteAddr(), err)
			return
		}
		domain := string(buf[:domainLen])
		n, err = io.ReadFull(clientConn, buf[:2]) // Read port
		if err != nil || n != 2 {
			log.Printf("SOCKS5 request from %s: Failed to read port for domain: %v", clientConn.RemoteAddr(), err)
			return
		}
		port := binary.BigEndian.Uint16(buf[:2])
		targetAddr = net.JoinHostPort(domain, strconv.Itoa(int(port)))
	case 0x04: // IPv6
		n, err = io.ReadFull(clientConn, buf[:16])
		if err != nil || n != 16 {
			log.Printf("SOCKS5 request from %s: Failed to read IPv6 address: %v", clientConn.RemoteAddr(), err)
			return
		}
		ip := net.IP(buf[:16]).String()
		n, err = io.ReadFull(clientConn, buf[:2]) // Port
		if err != nil || n != 2 {
			log.Printf("SOCKS5 request from %s: Failed to read port for IPv6: %v", clientConn.RemoteAddr(), err)
			return
		}
		port := binary.BigEndian.Uint16(buf[:2])
		targetAddr = net.JoinHostPort(ip, strconv.Itoa(int(port)))
	default:
		log.Printf("SOCKS5 request from %s: Unsupported ATYP: 0x%x", clientConn.RemoteAddr(), atyp)
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Address type not supported
		return
	}

	if c.cfg.LogDebug>=2 {
		log.Printf("SOCKS5 client %s requests connection to %s", clientConn.RemoteAddr(), targetAddr)
	}

	tunnels := c.tunnelManager.tunnels
	if len(tunnels) <= 0 {
		log.Printf("No available tunnels for SOCKS5 request from %s to %s. Responding with SOCKS5 failure.", clientConn.RemoteAddr(), targetAddr)
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Host unreachable
		return
	}

	sessionID := c.tunnelManager.GetNextSessionID()
	sess := NewSession(sessionID, clientConn, tunnels, c.sessions, c.cfg)
	c.sessions.Store(sessionID, sess)
	
	tunnel:=c.tunnelManager.GetAvailableTunnel()
	if tunnel == nil {
		log.Printf("No available tunnels for TCP request from %s to forward to %s", clientConn.RemoteAddr(), c.cfg.ForwardTarget)
		return
	}
	if c.cfg.LogDebug>=2 {
		log.Printf("SOCKS5 client %s select tunnel %d to %s", clientConn.RemoteAddr(), tunnel.ID, targetAddr)
	}
	


	var replymsg *protocol.TunnelMessage

	if replymsg, err = tunnel.WriteAndWait(protocol.NewOpenSessionMessage(sessionID, 1, c.cfg.ForwardTarget),sessionID,1,10); err != nil {
		log.Printf("[Session %d] Failed to send OPEN_SESSION message for SOCKS5 Proxy target %s to tunnel %d: %v", sessionID, c.cfg.ForwardTarget, tunnel.ID, err)
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		sess.Close()
		return
	}
	if c.cfg.ForwardTarget!= string(replymsg.Payload) {
		log.Printf("[Session %d] OPEN_SESSION ACK message received on tunnel %d, but target not match", sessionID, tunnel.ID)
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		sess.Close()
		return
	}

	
	// SOCKS5 success reply: VER=5, REP=0 (Success), RSV=0, BND.ADDR=0.0.0.0, BND.PORT=0
	// We don't know the actual bound address/port on the server side, so use 0.0.0.0:0
	if _, err = clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		log.Printf("[Session %d] Failed to send SOCKS5 success reply: %v", sessionID, err)
		sess.Close()
		return
	}


	if c.cfg.LogDebug>=2 {
		log.Printf("[Session %d] SOCKS5 connection to %s established over tunnel %d. Data forwarding started.", sessionID, targetAddr, tunnel.ID)
	}
	
	sess.nextSequenceID=replymsg.SequenceID+1
	sess.sendSequenceID=replymsg.SequenceID+1
	go sess.StartMessage()	
	sess.Start()

	log.Printf("[Session %d] SOCKS5 handling goroutine exited.", sessionID)
}

// listenForTCPConnections accepts incoming raw TCP connections.
func (c *Client) listenForTCPConnections() {
	defer func() {
		if c.listener != nil {
			c.listener.Close()
		}
		c.tunnelManager.Shutdown()
		if c.cfg.LogDebug>=2 {
			log.Println("TCP listener goroutine exited.")
		}
	}()
	if c.cfg.LogDebug>=2 {
		log.Println("TCP listener goroutine Started.")
	}
	
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			if tcpListener, ok := c.listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(time.Second))
			}
			conn, err := c.listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Error accepting TCP connection: %v", err)
				continue
			}
			log.Printf("TCP Connection from %s accepted .",conn.RemoteAddr())
			go c.handleTCPConnection(conn)
		}
	}
}

// handleTCPConnection sets up tunneling for a direct TCP connection.
func (c *Client) handleTCPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	if c.cfg.LogDebug>=2 {
		log.Printf("Handling new TCP connection from %s", clientConn.RemoteAddr())
	}

	tunnels := c.tunnelManager.tunnels
	if len(tunnels) <=0 {
		log.Printf("No available tunnels for TCP request from %s to forward to %s", clientConn.RemoteAddr(), c.cfg.ForwardTarget)
		return
	}
	log.Printf("%d Tunnels for TCP request ", len(tunnels))
	
	sessionID := c.tunnelManager.GetNextSessionID()
	sess := NewSession(sessionID, clientConn, tunnels, c.sessions, c.cfg)
	c.sessions.Store(sessionID, sess)
	if c.cfg.LogDebug>=2 {
		log.Printf("New session %d for TCP request from %s to forward to %s", sessionID, clientConn.RemoteAddr(), c.cfg.ForwardTarget)
		
	}
	
	tunnel:=c.tunnelManager.GetAvailableTunnel()
	if tunnel == nil {
		log.Printf("No available tunnels for TCP request from %s to forward to %s", clientConn.RemoteAddr(), c.cfg.ForwardTarget)
		return
	}

	if c.cfg.LogDebug>=2 {
		log.Printf("TCP client %s select tunnel %d to %s", clientConn.RemoteAddr(), tunnel.ID, c.cfg.ForwardTarget)
	}

	if c.cfg.LogDebug>=2 {
		log.Printf("Sending OpenSessionMessage for session %d to %s", sessionID, c.cfg.ForwardTarget)
	}
	var replymsg *protocol.TunnelMessage
	var err error
	if replymsg,err = tunnel.WriteAndWait(protocol.NewOpenSessionMessage(sessionID, 1, c.cfg.ForwardTarget),sessionID,1,10); err != nil {
		log.Printf("[Session %d] Failed to send OPEN_SESSION message for TCP target %s to tunnel %d: %v", sessionID, c.cfg.ForwardTarget, tunnel.ID, err)
		sess.Close()
		return
	}
	if c.cfg.ForwardTarget!= string(replymsg.Payload) {
		log.Printf("[Session %d] OPEN_SESSION ACK message received on tunnel %d, but target not match", sessionID, tunnel.ID)
		sess.Close()
		return
	}

	
	if c.cfg.LogDebug>=2 {
		log.Printf("[Session %d] OPEN_SESSION_ACK received, TCP connection from %s initiated forwarding to %s over tunnel %d.", sessionID, clientConn.RemoteAddr(), c.cfg.ForwardTarget, tunnel.ID)
	}
	
	sess.nextSequenceID=replymsg.SequenceID+1
	sess.sendSequenceID=replymsg.SequenceID+1
	go sess.StartMessage()	
	sess.Start()
	if c.cfg.LogDebug>=2 {
		log.Printf("[Session %d] TCP handling goroutine exited.", sessionID)
	
	}
}

// Stop gracefully shuts down the client.
func (c *Client) Stop() {
	log.Println("Shutting down client...")
	c.cancel()
	if c.listener != nil {
		c.listener.Close()
	}
	log.Println("Client shutdown initiated.")
}