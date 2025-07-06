package server

import (
	//"fmt"
	"io"
	"log"
	"net"
	"sync"
	//"sync/atomic"
	"math/rand"
	"time" 
	//"math"
	"github.com/aagun1234/ws3/config"
	"github.com/aagun1234/ws3/protocol"
)

// TargetSession represents an outbound connection to a target host on the server side.
type TargetSession struct {
	SessionID uint64
	nextSequenceID uint64
	sendSequenceID uint64
	cfg  *config.Config
	//wsConns    []*WebSocketConn // Reference back to the specific WebSocket connection
	//latency    map[*WebSocketConn]*atomic.Int64
	//lastPing   map[*WebSocketConn]*atomic.Int64
	maxping    uint64
	targetConn net.Conn      // The actual connection to the target
	manager   *SessionManager // Reference back to the manager
	closed    chan struct{}
	once      sync.Once
	mu             sync.RWMutex
	
	receiveBuffer  map[uint64]*protocol.TunnelMessage // 存储乱序到达的消息
	bufferCond     *sync.Cond                // 用于通知等待新消息的消费者
}

// NewTargetSession creates a new TargetSession.
func NewTargetSession(sessionID, maxping uint64, wsConn *WebSocketConn, manager *SessionManager, targetConn net.Conn, cfg *config.Config) *TargetSession {
	var wsConns []*WebSocketConn
	var tsess *TargetSession
	tsess, ok := manager.LoadSession(sessionID)
	if ok {
		if tsess == nil {
			log.Printf("[Server] LoadSession failed, got NIL.")
			return nil
		}
		if cfg.LogDebug>=2 {
			log.Printf("[Server] TargetSession %d exists,  adding WS to wsConns(%d).",  sessionID, len(tsess.manager.wsConns))
		}
		found:=false
		if cfg.LogDebug>=2 {
			log.Printf("[Server] sessionManager: %d", len(tsess.manager.wsConns))
		}
		for _, ws := range tsess.manager.wsConns {
			if ws == wsConn {
				found= true
				if cfg.LogDebug>=2 {
					log.Printf("[Server] WebSocket %d already in sessionManager, skip", wsConn.ID)			
				}
			}
		}
		if !found {
			tsess.manager.wsConns=append(tsess.manager.wsConns, wsConn)	
			if cfg.LogDebug>=2 {
				log.Printf("[Server] Adding WebSocket %d to sessionManager, %d", wsConn.ID, len(tsess.manager.wsConns))
			}
		}

	
		return tsess
	} else {
		if cfg.LogDebug>=2 {
			log.Printf("[Server] TargetSession %d not exists,  create new.",  sessionID)
		}
		wsConns=append(wsConns, wsConn)
		tsess := &TargetSession{
			SessionID:  sessionID,
			maxping:   maxping,
			//wsConns:    wsConns,
			targetConn: targetConn,
			manager:   manager,
			closed:    make(chan struct{}),
			cfg:	cfg,
			receiveBuffer: make(map[uint64]*protocol.TunnelMessage),
		}
		tsess.sendSequenceID=0
		found:=false
		if cfg.LogDebug>=2 {
			log.Printf("[Server] sessionManager: %d", len(tsess.manager.wsConns))
		}
		for _, ws := range tsess.manager.wsConns {
			if ws == wsConn {
				found= true
				if cfg.LogDebug>=2 {
					log.Printf("[Server] WebSocket %d already in sessionManager, skip", wsConn.ID)
				}
			}
		}
		if !found {
			tsess.manager.wsConns=append(tsess.manager.wsConns, wsConn)	
			if cfg.LogDebug>=2 {
				log.Printf("[Server] Adding WebSocket %d to sessionManager, %d", wsConn.ID, len(tsess.manager.wsConns))
			}
		}
		tsess.bufferCond = sync.NewCond(&tsess.mu) // 使用 session 的 RWMutex 作为 Cond 的 Locker
		if cfg.LogDebug>=2 {
			log.Printf("[Server] TargetSession %d ,  adding WS to wsConns(%d).", tsess.SessionID,len(tsess.manager.wsConns))
		}
		return tsess
	} 
	return nil
}




// StartMessageProcessing 启动一个 goroutine 来处理会话接收到的消息 remote->local
func (ts *TargetSession) StartMessage() { 
	go func() {
		for {
			if ts.cfg.LogDebug>=2 {
				log.Printf("[Server] [Message Buffer Processing], waiting for %d, Bufferlen: %d", ts.nextSequenceID,len(ts.receiveBuffer))
			}
			ts.mu.Lock()
			for { //循环等待直到有nextSequenceID
				msg, exists := ts.receiveBuffer[ts.nextSequenceID]
				if exists {
					if ts.cfg.LogDebug>=2 {
						log.Printf("[Server] [Message Buffer Processing] Message with seqID:%d, SessionID: %d, PayloadLen:%d",ts.nextSequenceID, msg.SessionID, len(msg.Payload))
					}
					if msg.SessionID==ts.SessionID && msg.SequenceID==ts.nextSequenceID {
						// 找到了期待的消息，可以处理了
						
						delete(ts.receiveBuffer, ts.nextSequenceID) // 从缓冲区中移除
						if ts.cfg.LogDebug>=2 {
							log.Printf("[Server] [Message Buffer Processing] Message delete from buffer, bufferlen: %d",len(ts.receiveBuffer))
						}
						ts.nextSequenceID++                       // 更新期待的下一条序列号
						ts.mu.Unlock()

						// 处理并转发消息
						if _, err := ts.targetConn.Write(msg.Payload); err != nil {
							log.Printf("[Server] [Message Buffer Processing] WS Error writing data to target for session %d: %v",  msg.SessionID, err)
							ts.Close() // Close session if client write fails
							return    // 退出处理循环
						} else {
							if ts.cfg.LogDebug>=2 {
								log.Printf("[Server] [Message Buffer Processing] session %d: Message sent to %s",  msg.SessionID, ts.targetConn.RemoteAddr())
							}
						}
						
						break // 跳出内层循环，继续处理下一条消息
					} else {
						
						delete(ts.receiveBuffer, ts.nextSequenceID) // 从缓冲区中移除
						if ts.cfg.LogDebug>=2 {
							log.Printf("[Server] [Message Buffer Processing] WS Message %d SessionID MisMatch Error, %d != %d, just remove from Buffer, bufferlen:%d",  msg.SequenceID, msg.SessionID, ts.SessionID, len(ts.receiveBuffer))
						}
					}
					
				} else {
					// 如果缓冲区中没有期待的消息，则等待
					ts.bufferCond.Wait() // 释放锁并等待 Signal
					// Signal 收到后，Wait 会重新获取锁并返回，然后再次检查条件
				}
			}

			// 检查会话是否已关闭
			select {
			case <-ts.closed:

				return // 会话关闭，退出 goroutine
			default:
				// 继续处理
			}
		}
	}()
	// Keep this goroutine alive until session is closed (waits on ts.closed)
	<-ts.closed
}



// Start initiates the data forwarding for the target session.
func (ts *TargetSession) Start() {
	defer ts.Close() // Ensure session is closed when goroutine exits

	// Goroutine to read from target and send over WebSocket
	go func() {
		buf := make([]byte, protocol.MaxPayloadSize)
		for {
			select {
			case <-ts.closed:
				return
			default:
				// Read from target with a deadline to make the loop responsive to ts.closed
				ts.targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := ts.targetConn.Read(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // Timeout, recheck closed status
					}
					if err != io.EOF {
						log.Printf("[Server Session %d] Error reading from target connection: %v", ts.SessionID, err)
					} 
					ts.Close()
					return
				}

				if n > 0 {
					
					wsConn:=ts.GetAvailableWS()
					
					if wsConn!=nil {
						if ts.cfg.LogDebug>=2 {
							log.Printf("[Server Session %d] Received %d bytes of data from target connection %s ", ts.SessionID, n, ts.targetConn.RemoteAddr())
							if ts.cfg.LogDebug>=4 {
								log.Printf("[Server Session %d] %v ", ts.SessionID,buf[:n])
							}
						}
						if err := wsConn.WriteMessage(protocol.NewDataMessage(ts.SessionID, ts.sendSequenceID, buf[:n])); err != nil {
							log.Printf("[Server Session %d] Error sending data (Seq:%d) over WebSocket: %v", ts.SessionID, ts.sendSequenceID, err)
							ts.Close()
							return
						}
						ts.sendSequenceID++
						if ts.cfg.LogDebug>=1 {
							log.Printf("[Server Session %d] %d bytes from %s to %s, SendSeq++=%d", ts.SessionID, n, ts.targetConn.RemoteAddr(), wsConn.conn.RemoteAddr(), ts.sendSequenceID)
						}
					} else {
						log.Printf("[Server Session %d] Error sending data (Seq:%d) NULL WebSocket: ", ts.SessionID, ts.sendSequenceID)
						ts.Close()
						return
					}
				}
			}
		}
	}()

	// Keep this goroutine alive until session is closed (waits on ts.closed)
	<-ts.closed
}


// GetAvailableTunnel selects a tunnel based on weighted random selection by latency.
func (ts *TargetSession) GetAvailableWS() *WebSocketConn {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var availableWSs []*WebSocketConn
	totalWeight := float64(0)
	if ts.cfg.LogDebug>=2 {
		log.Printf("[GetAvailableWS] Session %d: Total WebSockers: %d", ts.SessionID, len(ts.manager.wsConns))
	}
	// Filter connected and available tunnels and calculate total weight
	for _, ws := range ts.manager.wsConns {
		latency:= ws.Latency.Load()
		lastping:=ws.LastPing.Load()
		l1:=latency/ 1_000_000 //ms
		lp1:=(time.Now().UnixNano()-lastping)/1_000_000
		if ts.cfg.LogDebug>=2 {
			log.Printf("[GetAvailableWS] Session %d: WebSocket %d LastPing: %dms ago, Latency:%d", ts.SessionID, ws.ID, lp1, l1)
		}
		if time.Now().UnixNano()-lastping > int64(ts.maxping)*int64(time.Second) {
			if ts.cfg.LogDebug>=2 {
				log.Printf("[GetAvailableWS] Session %d: Last Ping expired, not available", ts.SessionID)
			}
			continue
		}
		
			//latency.Store(l1/ 1_000_000)
		var weight float64
		if l1 == 0 { // Prefer extremely low latency (e.g., initial state)
			weight = 1000.0 // Arbitrarily high weight
		} else {
			weight = 1.0 / float64(l1) // Lower latency -> higher weight
		}
		availableWSs = append(availableWSs, ws)
		if ts.cfg.LogDebug>=2 {
			log.Printf("[GetAvailableWS] Session %d: Adding Available WebSocket %d, total ws: %d, total weight: %d", ts.SessionID, ws.ID, len(availableWSs), totalWeight)
		}
		totalWeight += weight
		 
	}

	if len(availableWSs) == 0 {
		return nil
	}

	// Weighted random selection
	r := rand.Float64() * totalWeight
	if ts.cfg.LogDebug>=2 {
		log.Printf("[GetAvailableWS] Session %d: Weighted random selection: %d ", ts.SessionID, r)
	}
	for _, ws := range availableWSs {
		latency:= ws.Latency.Load()

		var weight float64
		if latency == 0 {
			weight = 1000.0
		} else {
			weight = 1.0 / float64(latency/ 1_000_000)
		}
		if r < weight {
			if ts.cfg.LogDebug>=2 {
				log.Printf("[GetAvailableWS] Session %d: WebSocket: %d, weight: %d ", ts.SessionID, ws.ID, weight)
			}
			return ws
		}
		r -= weight
	}

	// Fallback in case of floating point inaccuracies or if totalWeight was 0
	if len(availableWSs) > 0 {
		selected := availableWSs[rand.Intn(len(availableWSs))]
		return selected
	}
	return nil
}



// Close closes the target session and cleans up resources.
func (ts *TargetSession) Close() {
	ts.once.Do(func() {
		//log.Printf("[Server Session %d] Closing target session.", ts.SessionID)
		close(ts.closed)

		// Remove from manager's map
		ts.manager.DeleteSession(ts.SessionID)

		// Close target connection
		if ts.targetConn != nil {
			ts.targetConn.Close()
		}

		// Send close message back to client via WebSocket (if WS connection is still healthy)
		if len(ts.manager.wsConns)>0 {
			for _ , wsConn :=range ts.manager.wsConns {
				if wsConn!= nil && wsConn.IsConnected() { // Ensure WebSocket is still healthy before writing
					if err := wsConn.WriteMessage(protocol.NewCloseSessionMessage(ts.SessionID)); err != nil {
						log.Printf("[Server Session %d] Error sending close message back to client: %v", ts.SessionID, err)
					} else {
						break
					}
				}
			}
		}
	})
}

// SessionManager manages active target sessions on the server side.
type SessionManager struct {
	sessions *sync.Map // map[uint64]*TargetSession
	wsConns    []*WebSocketConn 
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: &sync.Map{},
	}
}

// StoreSession adds a new session to the manager.
func (sm *SessionManager) StoreSession(sessionID uint64, sess *TargetSession) {
	sm.sessions.Store(sessionID, sess)
}

// LoadSession retrieves a session from the manager.
func (sm *SessionManager) LoadSession(sessionID uint64) (*TargetSession, bool) {
	val, ok := sm.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	return val.(*TargetSession), true
}

// DeleteSession removes a session from the manager.
func (sm *SessionManager) DeleteSession(sessionID uint64) {
	sm.sessions.Delete(sessionID)
}

// CloseAllSessionsForWebSocket closes all sessions associated with a specific WebSocket connection.
func (sm *SessionManager) CloseAllSessionsForWebSocket(wsConn *WebSocketConn) {

	sm.sessions.Range(func(key, value interface{}) bool {
		sessionID := key.(uint64)
		sess := value.(*TargetSession)
		if sess==nil {
			return false
		}
		
		if len(sess.manager.wsConns) ==0 {
			log.Printf("[Server Session %d] Closing session due to no websocket.", sessionID)
			sess.Close() 
		} else if len(sess.manager.wsConns) ==1 {
			if sess.manager.wsConns[0]==wsConn {
				log.Printf("[Server Session %d] Closing session due to WebSocket disconnection.", sessionID)
				sess.Close() 
			}
		} else {
			for i, conn := range sess.manager.wsConns {
				if conn == wsConn {
					sess.manager.wsConns[i] = sess.manager.wsConns[len(sess.manager.wsConns)-1]
					log.Printf("[Server Session %d] Other websockets in this session, session will not close.", sessionID)
					break
				}
			}
		}
		return true
 	})
}


// CloseAllSessionsForWebSocket closes all sessions associated with a specific WebSocket connection.
func (sm *SessionManager) CloseAllSessionsForWebSocket1(wsConn *WebSocketConn) {
	sm.sessions.Range(func(key, value interface{}) bool {
		sessionID := key.(uint64)
		sess := value.(*TargetSession)
		if len(sess.manager.wsConns)>0 {
			log.Printf("[Server Session %d] Closing session due to WebSocket disconnection.", sessionID)
			sess.Close() // This will also delete it from the map
		}
		return true
	})
}