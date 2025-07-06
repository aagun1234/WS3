package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/gorilla/websocket"
	"github.com/aagun1234/ws3/config"
	"github.com/aagun1234/ws3/crypto"
	"github.com/aagun1234/ws3/protocol"
)

// WebSocketConn wraps a gorilla/websocket.Conn with encryption and mutex.
type WebSocketConn struct {
	ID   int
	conn *websocket.Conn
	mu   sync.Mutex
	cfg  *config.Config
	connected bool
	LastPing atomic.Int64
	Latency  atomic.Int64
	LOffset  atomic.Int64
}

// NewWebSocketConn creates a new WebSocketConn.
func NewWebSocketConn(id int, conn *websocket.Conn, cfg *config.Config) *WebSocketConn {
	return &WebSocketConn{
		ID:   id,
		conn: conn,
		cfg:  cfg,
		connected: true,
	}
}

// IsConnected checks if the WebSocket connection is active.
func (wc *WebSocketConn) IsConnected() bool {
	return wc.connected && wc.conn != nil
}

// WriteMessage encrypts and sends a TunnelMessage over the WebSocket.
func (wc *WebSocketConn) WriteMessage(msg *protocol.TunnelMessage) error {
	data, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	encryptedData, err := crypto.Encrypt([]byte(wc.cfg.SecretKey), data)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

//	wc.mu.Lock()
//	defer wc.mu.Unlock()
	if wc.conn == nil {
		return errors.New("websocket connection is nil or closed")
	}
	return wc.conn.WriteMessage(websocket.BinaryMessage, encryptedData)
}

// ReadMessage reads, decrypts, and unmarshals a TunnelMessage from the WebSocket.
func (wc *WebSocketConn) ReadMessage() (*protocol.TunnelMessage, error) {
	wc.mu.Lock()
	_, encryptedData, err := wc.conn.ReadMessage()
	wc.mu.Unlock()
	if err != nil {
		return nil, err
	}

	decryptedData, err := crypto.Decrypt([]byte(wc.cfg.SecretKey), encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	var msg protocol.TunnelMessage
	if err := msg.Unmarshal(decryptedData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	return &msg, nil
}

// Server is the B-side (WebSocket listener and outbound proxy)
type Server struct {
	cfg           *config.Config
	upgrader      websocket.Upgrader
	sessionManager *SessionManager
	listenerCount atomic.Uint64
	httpServers    []*http.Server
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewServer creates a new Server instance.
func NewServer(cfg *config.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg: cfg,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		sessionManager: NewSessionManager(),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start runs the WebSocket server.
func (s *Server) Start() error {

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	
	// 分割逗号分隔的地址
	addresses := strings.Split(s.cfg.ServerListenAddr, ",")
	for _, addr := range addresses {
		addr = strings.TrimSpace(addr) // 去除空格
		if addr == "" {
			continue
		}

		server := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		s.httpServers = append(s.httpServers, server)

		log.Printf("WebSocket server listening on %s", addr)

		go func(addr string, server *http.Server) {
			var err error
			if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
				log.Printf("Starting WSS (TLS) server on %s", addr)
				err = server.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
			} else {
				log.Printf("Starting WS (non-TLS) server on %s", addr)
				err = server.ListenAndServe()
			}

			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP server ListenAndServe error: %v", err)
			}
		}(addr, server)
	}

	<-s.ctx.Done()
	log.Println("Server stopped.")
	return nil
}

// handleWebSocket upgrades HTTP requests to WebSocket connections, with authentication.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	expectedAuth := "Bearer " + s.cfg.AuthToken
	if authHeader != expectedAuth {
		log.Printf("[Server] Unauthorized WebSocket connection attempt from %s (missing or invalid Authorization header)", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Printf("Upgrade to WebSocket for %s", r.RemoteAddr)
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket for %s: %v", r.RemoteAddr, err)
		return
	}

	connID := int(s.listenerCount.Add(1))
	wsConn := NewWebSocketConn(connID, conn, s.cfg)
	log.Printf("[Server] New WebSocket connection from %s (ID: %d)", conn.RemoteAddr(), connID)
	
	// found:=false
	// for _, ws := range s.sessionManager.wsConns {
		// if ws == wsConn {
			// found= true
			// break
		// }
	// }
	// if !found {
		// s.sessionManager.wsConns= append(s.sessionManager.wsConns, wsConn)
		// log.Printf("[Server] Adding WebSocket %d to sessionManager, total %d WebSockets", connID, len(s.sessionManager.wsConns))
	// }
	
	defer func() {
		if s.cfg.LogDebug>=2 {
			log.Printf("[Server] WebSocket %d from %s closed.", connID, conn.RemoteAddr())
		}
		wsConn.conn.Close()
		wsConn.connected = false
		s.sessionManager.CloseAllSessionsForWebSocket(wsConn)
	}()

	s.readWebSocketMessages(wsConn)
}

// readWebSocketMessages reads and processes messages from a single WebSocket connection.
func (s *Server) readWebSocketMessages(wsConn *WebSocketConn) {
	if s.cfg.LogDebug>=2 {
		log.Printf("[Server] WebSocket %d Start readWebSocketMessages",wsConn.ID)
	}
	for {
		select {
		case <-s.ctx.Done():
			if s.cfg.LogDebug>=2 {
				log.Printf("[Server] WebSocket %d readWebSocketMessages ctx.Done. ",wsConn.ID)
			}
			return
		default:
			msg, err := wsConn.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					if s.cfg.LogDebug>=2 {
						log.Printf("[Server] WebSocket %d closed normally: %v", wsConn.ID, err)
					}
				} else {
					log.Printf("[Server] Error reading message from WebSocket %d: %v", wsConn.ID, err)
				}
				wsConn.connected = false
				return
			}
			
			if s.cfg.LogDebug>=3 {
				log.Printf("[Server] WebSocket %d  MessageType: %d, SessionID: %d, SquenceID: %d, PayloadLength: %d",wsConn.ID, msg.Type, msg.SessionID, msg.SequenceID, len(msg.Payload))
		    }

			switch msg.Type {
			case protocol.MsgTypeOpenSession:
				// Server now connects directly to the target address provided by the client.
				// This makes the server truly general-purpose for proxying.
				targetAddr := string(msg.Payload)
				if s.cfg.LogDebug>=2 {
					log.Printf("[Server] WebSocket %d: OPEN_SESSION received, Opening session %d to client-requested target: %s", wsConn.ID, msg.SessionID, targetAddr)
				}
				if s.handleOpenSession(wsConn, msg.SessionID, msg.SequenceID+1, targetAddr) { // Use client-provided targetAddr
					//打开到目标的连接后，发送会话应答，消息与OPEN_SESSION相同（方向不同），后继会话的序列号从此开始递增
					//如果应答发送失败，结束这个会话
					if s.cfg.LogDebug>=2 {
						log.Printf("[Server] WebSocket %d: Target %s session %d Opened, sending OPEN_SESSION_ACK ", wsConn.ID, targetAddr, msg.SessionID)
					}
					time.Sleep(100 * time.Millisecond)
					if err := wsConn.WriteMessage(protocol.NewOpenSessionMessage(msg.SessionID, msg.SequenceID, targetAddr)); err != nil {
						log.Printf("[Server] WebSocket %d: Reply OPEN_SESSION Message Failed, SessionID:%d, SequenceID:%d", wsConn.ID, msg.SessionID, msg.SequenceID)
						if sess, ok := s.sessionManager.LoadSession(msg.SessionID); ok {
							sess.Close()
						}
					} else {
						if s.cfg.LogDebug>=2 {
							log.Printf("[Server] WebSocket %d: session %d Opened,  OPEN_SESSION_ACK sent", wsConn.ID, msg.SessionID)
						}
					}
				} else {
					log.Printf("[Server] WebSocket %d: Open session Failed, sending CLOSE_SESSION", wsConn.ID)
					time.Sleep(100 * time.Millisecond)
					if err := wsConn.WriteMessage(protocol.NewCloseSessionMessage(msg.SessionID)); err != nil {
						log.Printf("[Server] WebSocket %d: Open session %d Failed", wsConn.ID)
					}
					if sess, ok := s.sessionManager.LoadSession(msg.SessionID); !ok {
						log.Printf("[Server] WebSocket %d: Session %d Store failed", wsConn.ID, msg.SessionID)
						sess.Close()
					}
				}
				
				
			case protocol.MsgTypeData:
				if sess, ok := s.sessionManager.LoadSession(msg.SessionID); ok {
					if s.cfg.LogDebug>=2 {
						log.Printf("[Server] WebSocket %d: DataMessage in Session(%d) Seq(%d) received, saving to Buffer...", wsConn.ID, msg.SessionID, msg.SequenceID)
					}
					// 将消息放入会话的接收缓冲区
					sess.mu.Lock()
					sess.receiveBuffer[msg.SequenceID] = msg
					sess.bufferCond.Signal() // 通知等待中的消费者有新消息到达
					
					sess.mu.Unlock()
					
					wsConn.LastPing.Store(time.Now().UnixNano())
					if s.cfg.LogDebug>=2 {
						log.Printf("[Server] WebSocket %d: DataMessage saved to Session Buffer, bufferLen: %d, LastPing %dms stored", wsConn.ID, len(sess.receiveBuffer),wsConn.LastPing.Load()/1_000_000)
					}
					if s.cfg.LogDebug>=1 {
						log.Printf("[Server] WebSocket %d: %d bytes from %s to %s buffered, Sequence: %d", wsConn.ID, len(msg.Payload), wsConn.conn.RemoteAddr(), sess.targetConn.RemoteAddr(),msg.SequenceID)
					}
					
					//这里不直接转发，等待会话协程处理缓冲区
					// if _, err := sess.targetConn.Write(msg.Payload); err != nil {
						// log.Printf("[Server] WS %d: Error writing data to target for session %d: %v", wsConn.ID, msg.SessionID, err)
						// sess.Close()
					// }
				} else {
					if s.cfg.LogDebug>=2 {
						log.Printf("[Server] WebSocket %d: Received data for unknown session %d, clos", wsConn.ID, msg.SessionID)
					}
					wsConn.WriteMessage(protocol.NewCloseSessionMessage(msg.SessionID))
				}
			case protocol.MsgTypeCloseSession:
				if sess, ok := s.sessionManager.LoadSession(msg.SessionID); ok {
					if s.cfg.LogDebug>=2 {
						log.Printf("[Server] WebSocket %d: Received close for session %d from client.", wsConn.ID, msg.SessionID)
					}
					sess.Close()
				} else {
					log.Printf("[Server] WebSocket %d: Received close for unknown session %d from client.", wsConn.ID, msg.SessionID)
				}
			case protocol.MsgTypePing:
				if timestamp, err := protocol.GetPingTimestamp(msg); err == nil {
					wsConn.LastPing.Store(time.Now().UnixNano())
					lastlatency:=wsConn.Latency.Load()
					loffset:=wsConn.LOffset.Load()
					if (time.Now().UnixNano() - timestamp + loffset)<0 {
						loffset= timestamp -time.Now().UnixNano()
						wsConn.LOffset.Store(loffset)
					}
					latency:=((time.Now().UnixNano() - timestamp + loffset)*7+lastlatency*3)/10
					wsConn.Latency.Store(latency)
					if s.cfg.LogDebug>=3 {
						log.Printf("[Server] WebSocket %d: Received ping, latency: %d ms (offset: %d), sending pong.", wsConn.ID, loffset, latency/1_000_000)
					}					
					wsConn.WriteMessage(protocol.NewPongMessage(timestamp))	
				} else {
					log.Printf("[Server] WebSocket %d: Invalid ping message: %v", wsConn.ID, err)
				}
			default:
				log.Printf("[Server] WebSocket %d: Received unknown message type: %d", wsConn.ID, msg.Type)
			}
		}
	}
	if s.cfg.LogDebug>=2 {
		log.Printf("[Server] WebSocket %d readWebSocketMessages end. ",wsConn.ID)
	}
}

// handleOpenSession establishes a connection to the target host.
func (s *Server) handleOpenSession(wsConn *WebSocketConn, sessionID , startSeqID uint64, targetAddr string) bool {
	
	var targetConn net.Conn 
	var err error
	if s.cfg.LogDebug>=2 {
		log.Printf("[Server] WebSocket %d: handleOpenSession start ", wsConn.ID)
	}
	sess, ok := s.sessionManager.LoadSession(sessionID)
	
	
	if !ok {//如果是新建会话，说明需要向目标发起连接
		// Server now dials directly to the targetAddr provided by the client.
		if s.cfg.LogDebug>=2 {
			log.Printf("[Server] WebSocket %d: Dial to %s ", wsConn.ID, targetAddr)
		}
		targetConn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[Server] [handleOpenSession] WebSocket %d: Failed to connect to client-requested target %s for session %d: %v", wsConn.ID, targetAddr, sessionID, err)
			wsConn.WriteMessage(protocol.NewCloseSessionMessage(sessionID))
			return false
		}

		if s.cfg.LogDebug>=2 {
			log.Printf("[Server] [handleOpenSession] WebSocket %d: Successfully connected to client-requested target %s for session %d.", wsConn.ID, targetAddr, sessionID)
		}
	} 
	
	log.Printf("[Server] WebSocket %d: Init TargetSession.", wsConn.ID )
	sess = NewTargetSession(sessionID, uint64(s.cfg.PingInterval*3), wsConn, s.sessionManager, targetConn, s.cfg)
	if sess!=nil {
		sess.nextSequenceID=startSeqID
		sess.sendSequenceID=startSeqID
		s.sessionManager.StoreSession(sessionID, sess)
	
		log.Printf("[Server] WebSocket %d: TargetSession initialized, total %d websockets",  sessionID, len(sess.wsConns))
	
		if s.cfg.LogDebug>=2 {
			log.Printf("[Server] WebSocket %d: Target handling goroutine for session %d Started.", wsConn.ID, sessionID)
		}
		go sess.StartMessage()
		go sess.Start()
		if s.cfg.LogDebug>=2 {
			log.Printf("[Server] WebSocket %d: handleOpenSession end. ", wsConn.ID)
		}
		return true
	} else {
		log.Printf("[Server] WebSocket %d: TargetSession create Failed, handleOpenSession end. ", wsConn.ID)
		return false
	}
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	log.Println("Shutting down server...")
	s.cancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, serv:=range s.httpServers {
		if serv != nil {
			if err := serv.Shutdown(shutdownCtx); err != nil {
				log.Printf("HTTP server shutdown error: %v", err)
			}
		}
	}
	log.Println("Server shutdown initiated.")
}