// (少量修改：remoteAddr 改为 RemoteServerAddr)

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	//"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	//"net/url" 
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/gorilla/websocket"
	"github.com/aagun1234/ws3/config"
	"github.com/aagun1234/ws3/crypto"
	"github.com/aagun1234/ws3/protocol"
)

// Tunnel represents a single WebSocket connection in the tunnel pool.
type Tunnel struct {
	ID        int
	remoteAddr string
	Conn      *websocket.Conn
	mu        sync.RWMutex
	latency   atomic.Int64    // in nanoseconds
	lastHeartbeat atomic.Int64 // UnixNano of last successful ping/pong
	closeChan chan struct{}
	config    *config.Config
	connected bool // Simple boolean for current connection status

	// Health Check / Backoff fields
	available         atomic.Bool  // True if currently considered available for use (not in backoff)
	reconnectAttempts atomic.Int32 // Consecutive failed connection attempts
	nextReconnectTime atomic.Int64 // UnixNano of when the next reconnect attempt is allowed
	cancel            context.CancelFunc // Context cancel for goroutines associated with this tunnel
	OpenACKs 	      map[uint64]chan protocol.TunnelMessage
	OpenACKMutex      sync.Mutex      // 待处理请求锁
	
}

// Latency returns the current average latency of the tunnel in milliseconds.
func (t *Tunnel) Latency() int64 {
	return t.latency.Load() / 1_000_000 // Convert ns to ms
}

// IsConnected checks if the tunnel is currently active and healthy.
// It considers the internal 'connected' status, 'available' status (backoff),
// and recent heartbeat.
func (t *Tunnel) IsConnected() bool {
	// Must be connected internally, have a live Conn object, and be marked 'available' (not in backoff)
	if !t.connected || t.Conn == nil || !t.available.Load() {

		return false
	}
	// Also check for recent heartbeat to ensure liveness
	return time.Now().UnixNano()-t.lastHeartbeat.Load() < int64(t.config.PingInterval*3)*int64(time.Second)
}


func (t *Tunnel) WriteAndWait(msg *protocol.TunnelMessage, sessionID, sequenceID uint64, timeout int) (*protocol.TunnelMessage, error) {

	ch := make(chan protocol.TunnelMessage, 1)
	t.OpenACKMutex.Lock()
	t.OpenACKs[sessionID<<32|sequenceID] = ch
	t.OpenACKMutex.Unlock()
	
	defer func() {
		t.OpenACKMutex.Lock()
		delete(t.OpenACKs, sessionID<<32|sequenceID)
		t.OpenACKMutex.Unlock()
	}()
	
	if err := t.WriteMessage(msg); err != nil {
		return nil, err
	}
		
	select {
	case resp := <-ch:
		return &resp, nil
	case  <-time.After(time.Duration(timeout) * time.Second):
		return nil, fmt.Errorf("Wait for Reply Timeout")
	}
}

// WriteMessage encrypts and sends a TunnelMessage over the WebSocket.
func (t *Tunnel) WriteMessage(msg *protocol.TunnelMessage) error {
	data, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}
	encryptedData, err := crypto.Encrypt([]byte(t.config.SecretKey), data)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	if t.Conn == nil {
		return errors.New("websocket connection is nil or closed")
	}
	deadline := time.Now().Add(4 * time.Second) // 10秒超时
    if err := t.Conn.SetWriteDeadline(deadline); err != nil {
        return fmt.Errorf("failed to set write deadline: %w", err)
    }
	
	return t.Conn.WriteMessage(websocket.BinaryMessage, encryptedData)
}

// ReadMessage reads, decrypts, and unmarshals a TunnelMessage from the WebSocket.
func (t *Tunnel) ReadMessage() (*protocol.TunnelMessage, error) {
	t.mu.Lock() // Use lock for ReadMessage as well to prevent concurrent reads
	_, encryptedData, err := t.Conn.ReadMessage()
	t.mu.Unlock()	
	if err != nil {
		return nil, err
	}
	
	decryptedData, err := crypto.Decrypt([]byte(t.config.SecretKey), encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	var msg protocol.TunnelMessage
	if err := msg.Unmarshal(decryptedData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	return &msg, nil
}

// TunnelManager manages multiple WebSocket tunnels.
type TunnelManager struct {
	tunnels    []*Tunnel
	remoteServerAddr []string // Renamed for clarity
	cfg        *config.Config
	dialer     *websocket.Dialer
	// A map to store sessionID to client.Session mapping, used by the tunnel reader goroutine
	// to forward data back to the client.
	sessions       *sync.Map // map[uint64]*client.Session
	nextSessionID  atomic.Uint64
	mu             sync.RWMutex // Protects tunnels slice
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewTunnelManager creates a new TunnelManager.
func NewTunnelManager(cfg *config.Config, sessions *sync.Map) *TunnelManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	
	var addresses []string
	//addresses := strings.Split(tm.remoteServerAddr, ",")
	for _, addr := range strings.Split(cfg.RemoteServerAddr, ",") {
		addr = strings.TrimSpace(addr) // 去除空格
		if addr == "" {
			continue
		}
		addresses = append(addresses, addr)
	}
	tm := &TunnelManager{
		remoteServerAddr: addresses, // Use new field
		cfg:        cfg,
		dialer:     websocket.DefaultDialer,
		sessions:   sessions,
		ctx:        ctx,
		cancel:     cancel,
	}
	tm.nextSessionID.Store(uint64(time.Now().UnixNano())) // Start with a somewhat random large number



	// Configure TLS for the dialer if WSS is used
	for _, addr := range tm.remoteServerAddr {
		addr = strings.TrimSpace(addr) // 去除空格
		if strings.HasPrefix(addr, "wss://") {
			tm.dialer.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: tm.cfg.InsecureSkipVerify, // WARNING: Only for testing with self-signed certs!
			}
			if tm.cfg.InsecureSkipVerify {
				log.Println("WARNING: Client is configured to skip TLS certificate verification (INSECURE_SKIP_VERIFY=true). Do not use in production.")
			}
		}
	}



	tm.tunnels = make([]*Tunnel, cfg.TunnelCount)
	for i := 0; i < cfg.TunnelCount; i++ {
		tunnelCtx, tunnelCancel := context.WithCancel(tm.ctx)
		t := &Tunnel{
			ID:        i,
			remoteAddr: addresses[i%len(addresses)],
			latency:   atomic.Int64{},
			closeChan: make(chan struct{}),
			config:    cfg,
			cancel:    tunnelCancel,
			OpenACKs:  make(map[uint64]chan protocol.TunnelMessage),
		}
		t.latency.Store(math.MaxInt64) // Initialize with max latency
		t.lastHeartbeat.Store(0)
		t.available.Store(false) // Initially not available until connected
		t.reconnectAttempts.Store(0)
		t.nextReconnectTime.Store(0)
		tm.tunnels[i] = t
		if tm.cfg.LogDebug>=2 {
			log.Printf("[NewTunnelManager] [Tunnel %d] Tunnel add .", t.ID)
		}
		go tm.connectAndMonitorTunnel(tunnelCtx, t)
	}
	return tm
}

// connectAndMonitorTunnel attempts to connect a tunnel and keeps it alive, with exponential backoff.
func (tm *TunnelManager) connectAndMonitorTunnel(ctx context.Context, t *Tunnel) {
	defer func() {
		if tm.cfg.LogDebug>=2 {
			log.Printf("[Monitor] [Tunnel %d] Monitoring routine exited.", t.ID)
		}
		t.cancel() // Ensure this tunnel's context is cancelled
		t.mu.Lock()
		if t.Conn != nil {
			t.Conn.Close()
			t.Conn = nil
		}
		t.connected = false
		t.available.Store(false)
		t.mu.Unlock()
	}()
	if tm.cfg.LogDebug>=2 {
		log.Printf("[Monitor] [Tunnel %d] Monitoring routine Started.", t.ID)
	}
	for {
		select {
		case <-ctx.Done():
			if tm.cfg.LogDebug>=2 {
				log.Printf("[Monitor] [Tunnel %d] Context cancelled, shutting down tunnel routine.", t.ID)
			}
			return
		default:
			// Continue
		}

		// Check if we are in a backoff period
		if !t.available.Load() && t.nextReconnectTime.Load() > 0 && time.Now().UnixNano() < t.nextReconnectTime.Load() {
			delay := time.Unix(0, t.nextReconnectTime.Load()).Sub(time.Now())
			if delay > 0 {
				if tm.cfg.LogDebug>=2 {
					log.Printf("[Monitor] [Tunnel %d] In backoff. Next attempt in %s.", t.ID, delay.Round(time.Second))
				}
				time.Sleep(delay) // Wait until next reconnect time
				continue
			}
		}

		// If not connected or not available (after backoff), attempt connection
		if !t.connected || t.Conn == nil || !t.available.Load() {
			if tm.cfg.LogDebug>=2 {
				log.Printf("[Monitor] [Tunnel %d] Attempting to connect to %s (attempt #%d)...", t.ID, t.remoteAddr, t.reconnectAttempts.Load()+1)
			}
			requestHeader := http.Header{}
			requestHeader.Add("Authorization", "Bearer "+t.config.AuthToken)
			
			conn, _, err := tm.dialer.DialContext(ctx, t.remoteAddr, requestHeader)
			t.mu.Lock()
			
			if t.Conn != nil { // Close old connection if any
				if tm.cfg.LogDebug>=2 { 
					log.Printf("[Monitor] [Tunnel %d] Closing old Conn...", t.ID )
				}
				t.Conn.Close()
			}
			t.Conn = conn
			t.connected = (err == nil) // Update connected status based on dial result
			t.mu.Unlock()

			if err != nil {
				t.reconnectAttempts.Add(1)
				// Exponential backoff calculation
				delaySeconds := float64(t.config.BaseReconnectDelay) * math.Pow(2, float64(t.reconnectAttempts.Load()-1))
				if delaySeconds > float64(t.config.MaxReconnectDelay) {
					delaySeconds = float64(t.config.MaxReconnectDelay)
				}
				delay := time.Duration(delaySeconds) * time.Second

				log.Printf("[Monitor] [Tunnel %d] Failed to connect: %v. Retrying in %v...", t.ID, err, delay.Round(time.Second))
				t.latency.Store(math.MaxInt64) // Set high latency on disconnect
				t.lastHeartbeat.Store(0)
				t.available.Store(false)
				t.nextReconnectTime.Store(time.Now().Add(delay).UnixNano())
				time.Sleep(1 * time.Second) // Small sleep before re-evaluating loop
				continue // Go back to loop start to re-check backoff
			}

			t.latency.Store(0) // Reset latency on new connection
			t.lastHeartbeat.Store(time.Now().UnixNano())
			t.reconnectAttempts.Store(0) // Reset attempts on successful connection
			t.available.Store(true)      // Mark available
			t.nextReconnectTime.Store(0) // Reset next reconnect time
			if tm.cfg.LogDebug>=2 {
				log.Printf("[Monitor] [Tunnel %d] Connected to %s, %v", t.ID, t.remoteAddr,t.connected)
			}
			// Start read and ping handlers for the newly connected tunnel
			
			go tm.handleTunnelRead(ctx, t)
			go tm.handleTunnelPing(ctx, t)
			if tm.cfg.LogDebug>=3 {
				log.Printf("[Monitor] [Tunnel %d] Sending first Ping %s, %v", t.ID, t.remoteAddr,t.connected)
			}
			if err := t.WriteMessage(protocol.NewPingMessage(time.Now().UnixNano())); err != nil {
				log.Printf("[TunnelPing] [Tunnel %d] Error sending ping: %v. Marking disconnected/unavailable.", t.ID, err)
			}
			
		}

		// Keep routine alive while connected, primarily waits for disconnect or context cancellation
		select {
		case <-ctx.Done():
			continue // Check context.Done again at loop start
		case <-time.After(time.Second): // Periodically check connection status
			if !t.IsConnected() { // This checks for heartbeat validity and general connection health
				log.Printf("[Monitor] [Tunnel %d] Connection seemed unhealthy or broken. Initiating reconnect cycle...", t.ID)
				if tm.cfg.LogDebug>=2 {
					log.Printf("[Tunnel %d] connected %v, Conn %v, Available %v \n", t.ID, t.connected,(t.Conn!=nil),t.available.Load())
				}
				t.mu.Lock()
				if t.Conn != nil {
					t.Conn.Close()
					t.Conn = nil
				}
				t.connected = false
				t.mu.Unlock()
				t.available.Store(false) // Mark unavailable to trigger backoff in next loop iteration
			}
		}
	}
}

// handleTunnelRead handles incoming messages from a WebSocket tunnel.
func (tm *TunnelManager) handleTunnelRead(ctx context.Context, t *Tunnel) {
	defer func() {
		if tm.cfg.LogDebug>=2 {
			log.Printf("[TunnelRead] [Tunnel %d] Read handler exited. Marking tunnel as disconnected/unavailable.", t.ID)
		}
		t.mu.Lock()
		if t.Conn != nil {
			t.Conn.Close()
			t.Conn = nil
		}
		t.connected = false
		t.mu.Unlock()
		t.available.Store(false) // Mark unavailable to trigger reconnect logic
		// Clean up any sessions associated with this tunnel that might be stuck
		// tm.sessions.Range(func(key, value interface{}) bool {
			// sessionID := key.(uint64)
			// sess := value.(*Session)
			// if sess.tunnel == t {
				// if tm.cfg.LogDebug>=2 {
					// log.Printf("[TunnelRead] [Tunnel %d] Cleaning up session %d due to tunnel disconnection.", t.ID, sessionID)
				// }
				// sess.Close() // This will also remove it from tm.sessions
			// }
			// return true
		// })
	}()
	if tm.cfg.LogDebug>=2 {
		log.Printf("[TunnelRead] [Tunnel %d] Read handler Start", t.ID,)
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := t.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					if tm.cfg.LogDebug>=2 {
						log.Printf("[TunnelRead] [Tunnel %d] WebSocket closed normally: %v", t.ID, err)
					}
				} else {
					log.Printf("[TunnelRead] [Tunnel %d] Error reading message: %v", t.ID, err)
				}
				return // Exit read loop on error
			}

			if tm.cfg.LogDebug>=3 {
				log.Printf("[TunnelRead] [Tunnel %d] MessageType: %d, SessionID: %d, SquenceID: %d, PayloadLength: %d",
					t.ID, msg.Type, msg.SessionID, msg.SequenceID, len(msg.Payload))
			}

			t.lastHeartbeat.Store(time.Now().UnixNano()) // Update heartbeat on any received message

			switch msg.Type {
			case protocol.MsgTypeOpenSession:
				t.OpenACKMutex.Lock()
				if ch, ok := t.OpenACKs[msg.SessionID<<32|msg.SequenceID]; ok {
					ch <- *msg
					delete(t.OpenACKs, msg.SessionID<<32|msg.SequenceID)
				}
				t.OpenACKMutex.Unlock()
				
			case protocol.MsgTypeData:
				if val, ok := tm.sessions.Load(msg.SessionID); ok {
					sess := val.(*Session)
					if tm.cfg.LogDebug>=2 {
						log.Printf("[TunnelRead] [Tunnel %d] Received %d bytes data for session %d, Seq:%d, sending to %s.", t.ID, len(msg.Payload), msg.SessionID, msg.SequenceID, sess.clientConn.RemoteAddr())
					}
					// 将消息放入会话的接收缓冲区
					sess.mu.Lock()
					sess.receiveBuffer[msg.SequenceID] = msg
					sess.bufferCond.Signal() // 通知等待中的消费者有新消息到达
					sess.mu.Unlock()
					if tm.cfg.LogDebug>=1 {
						log.Printf("[TunnelRead] [Tunnel %d] session %d: %d bytes from %s to , Sequence:%d, sending to %s.", t.ID,  msg.SessionID, len(msg.Payload), t.Conn.RemoteAddr(), sess.clientConn.RemoteAddr(), msg.SequenceID, )
					}
					//这里不直接转发，等待会话协程处理缓冲区
					// if _, err := sess.clientConn.Write(msg.Payload); err != nil {
						// log.Printf("[TunnelRead] [Tunnel %d] Error writing data to client connection %d: %v", t.ID, msg.SessionID, err)
						// sess.Close() // Close session if client write fails
					// }
				} else {
					log.Printf("[TunnelRead] [Tunnel %d] Received data for unknown session %d, Closing session.", t.ID, msg.SessionID)
					// Potentially send a close message back to server if session unknown
					t.WriteMessage(protocol.NewCloseSessionMessage(msg.SessionID))
				}
			case protocol.MsgTypeCloseSession:
				if val, ok := tm.sessions.Load(msg.SessionID); ok {
					if tm.cfg.LogDebug>=2 {
						log.Printf("[TunnelRead] [Tunnel %d] Received close for session %d from server.", t.ID, msg.SessionID)
					}
					val.(*Session).Close() // This also removes it from tm.sessions
				} else {
					log.Printf("[TunnelRead] [Tunnel %d] Received close for unknown session %d from server.", t.ID, msg.SessionID)
				}
			case protocol.MsgTypePong:
				if timestamp, err := protocol.GetPingTimestamp(msg); err == nil {
					rtt := (time.Now().UnixNano() - timestamp)*7+t.latency.Load()*3
					t.latency.Store(rtt/10)
					if tm.cfg.LogDebug>=3 {
						log.Printf("[TunnelRead] [Tunnel %d] Ping-Pong RTT: %d ms", t.ID, rtt/10_000_000)
					}
					
				} else {
					log.Printf("[TunnelRead] [Tunnel %d] Invalid pong message: %v", t.ID, err)
				}
			default:
				log.Printf("[Tunnel %d] Received unknown message type: %d", t.ID, msg.Type)
			}
		}
	}
}

// handleTunnelPing periodically sends ping messages to measure latency.
func (tm *TunnelManager) handleTunnelPing(ctx context.Context, t *Tunnel) {
	ticker := time.NewTicker(time.Duration(tm.cfg.PingInterval) * time.Second)
	defer ticker.Stop()
	
	if tm.cfg.LogDebug>=2 {
		log.Printf("[TunnelPing] [Tunnel %d] Ping handler Started.", t.ID)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			last:=t.lastHeartbeat.Load()
			curr:=time.Now().UnixNano()
			elapsed := int(float64(curr-last)/1e9)
			if elapsed >= tm.cfg.PingInterval {
				newInterval := time.Duration(time.Duration(tm.cfg.PingInterval) * time.Second) 
				ticker.Stop()                         // 停止旧的
				ticker = time.NewTicker(newInterval)  // 创建新的
			
				if t.IsConnected() { // Only ping if considered connected and available
					if tm.cfg.LogDebug>=4 {
						log.Printf("[TunnelPing] [Tunnel %d] Sending Ping Message", t.ID)
					}
					if err := t.WriteMessage(protocol.NewPingMessage(time.Now().UnixNano())); err != nil {
						log.Printf("[TunnelPing] [Tunnel %d] Error sending ping: %v. Marking disconnected/unavailable.", t.ID, err)
						t.mu.Lock()
						if t.Conn != nil {
							t.Conn.Close()
							t.Conn = nil
						}
						t.connected = false
						t.mu.Unlock()
						t.available.Store(false) // Mark unavailable to trigger reconnect logic
						
						return // Exit ping handler, connection is broken
					}
				
				} else {
					log.Printf("[TunnelPing] [Tunnel %d] Not connected or available, stopping ping.", t.ID)
					return // Tunnel is not connected, stop pinging
				}
			} else {
				newInterval := time.Duration(time.Duration(tm.cfg.PingInterval-elapsed) * time.Second)
				ticker.Stop()                         // 停止旧的
				ticker = time.NewTicker(newInterval)  // 创建新的
			}
		}
	}
	if tm.cfg.LogDebug>=2 { 
		log.Printf("[TunnelPing] [Tunnel %d] Ping handler exited.", t.ID) 
	}
}

// GetNextSessionID generates a unique session ID.
func (tm *TunnelManager) GetNextSessionID() uint64 {
	return tm.nextSessionID.Add(1)
}

// GetAvailableTunnel selects a tunnel based on weighted random selection by latency.
func (tm *TunnelManager) GetAvailableTunnel() *Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var availableTunnels []*Tunnel
	totalWeight := float64(0)

	// Filter connected and available tunnels and calculate total weight
	for _, t := range tm.tunnels {
		if t.IsConnected() { // This now checks connected, available, and heartbeat
			latencyMs := t.Latency()
			var weight float64
			if latencyMs == 0 { // Prefer extremely low latency (e.g., initial state)
				weight = 1000.0 // Arbitrarily high weight
			} else {
				weight = 1.0 / float64(latencyMs) // Lower latency -> higher weight
			}
			availableTunnels = append(availableTunnels, t)
			totalWeight += weight
		} else if tm.cfg.LogDebug>=2 {
			log.Printf("[Tunnel %d] Not available: connected=%t, available=%t, latency=%d, lastHeartbeat=%v, nextReconnect=%v",
				t.ID, t.connected, t.available.Load(), t.Latency(),
				time.Unix(0, t.lastHeartbeat.Load()), time.Unix(0, t.nextReconnectTime.Load()))
		}
	}

	if len(availableTunnels) == 0 {
		return nil
	}

	// Weighted random selection
	r := rand.Float64() * totalWeight
	for _, t := range availableTunnels {
		latencyMs := t.Latency()
		var weight float64
		if latencyMs == 0 {
			weight = 1000.0
		} else {
			weight = 1.0 / float64(latencyMs)
		}
		if r < weight {
			if tm.cfg.LogDebug>=2 {
				log.Printf("Selected tunnel %d (latency: %dms, weight: %.2f)", t.ID, latencyMs, weight)
			}
			return t
		}
		r -= weight
	}

	// Fallback in case of floating point inaccuracies or if totalWeight was 0
	if len(availableTunnels) > 0 {
		selected := availableTunnels[rand.Intn(len(availableTunnels))]
		log.Printf("Fallback: Randomly selected tunnel %d", selected.ID)
		return selected
	}
	return nil
}

// Shutdown gracefully shuts down all tunnels.
func (tm *TunnelManager) Shutdown() {
	log.Println("Shutting down TunnelManager...")
	tm.cancel() // Signal all tunnel routines to stop
	// Give a moment for goroutines to clean up
	time.Sleep(2 * time.Second)
	log.Println("TunnelManager shut down complete.")
}