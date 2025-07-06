package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"math/rand"
)

// MessageType defines the type of message being sent over the tunnel.
type MessageType byte

const (
	MsgTypeOpenSession  MessageType = 0x01 // Request to open a new session (connection to target)
	MsgTypeData         MessageType = 0x02 // Data payload for an existing session
	MsgTypeCloseSession MessageType = 0x03 // Request to close an existing session
	MsgTypePing         MessageType = 0x04 // Ping for latency measurement
	MsgTypePong         MessageType = 0x05 // Pong response
)

const (
	// HeaderSize is the fixed size of our custom message header:
	// 1 byte (MsgType) + 8 bytes (SessionID) + 8 bytes (sequence) 
	HeaderSize = 1 + 8 + 8
	// MaxPayloadSize is an arbitrary limit for a single message payload.
	// Large data streams will be split into multiple MsgTypeData messages.
	MaxPayloadSize = 65535 // ~64KB
)

// TunnelMessage represents a message exchanged over the WebSocket tunnel.
type TunnelMessage struct {
	Type      MessageType
	SessionID uint64
	SequenceID uint64
	Payload   []byte // Can be target address, actual data, or ping timestamp
}

// Marshal serializes a TunnelMessage into a byte slice.
func (tm *TunnelMessage) Marshal() ([]byte, error) {
	header := make([]byte, HeaderSize)
	header[0] = byte(tm.Type)
	binary.BigEndian.PutUint64(header[1:9], tm.SessionID)
	binary.BigEndian.PutUint64(header[9:17], tm.SequenceID)
	return append(header, tm.Payload...), nil
}

// Unmarshal deserializes a byte slice into a TunnelMessage.
func (tm *TunnelMessage) Unmarshal(data []byte) error {
	if len(data) < HeaderSize {
		return errors.New("message data too short for header")
	}

	tm.Type = MessageType(data[0])
	tm.SessionID = binary.BigEndian.Uint64(data[1:9])
	tm.SequenceID = binary.BigEndian.Uint64(data[9:17])
	tm.Payload = data[HeaderSize:]
	return nil
}

// NewOpenSessionMessage creates an OPEN_SESSION message.
func NewOpenSessionMessage(sessionID, seqID uint64, targetAddr string) *TunnelMessage {
	return &TunnelMessage{
		Type:      MsgTypeOpenSession,
		SessionID: sessionID,
		SequenceID: seqID,
		Payload:   []byte(targetAddr),
	}
}

// NewDataMessage creates a DATA message.
func NewDataMessage(sessionID , seqID uint64, data []byte) *TunnelMessage {
	return &TunnelMessage{
		Type:      MsgTypeData,
		SessionID: sessionID,
		SequenceID: seqID,
		Payload:   data,
	}
}

// NewCloseSessionMessage creates a CLOSE_SESSION message.
func NewCloseSessionMessage(sessionID uint64) *TunnelMessage {
	return &TunnelMessage{
		Type:      MsgTypeCloseSession,
		SessionID: sessionID,
		SequenceID: 0,
	}
}

// NewPingMessage creates a PING message with a timestamp.
func NewPingMessage(timestamp int64) *TunnelMessage {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(timestamp))
	rand.Seed(time.Now().UnixNano())
	randomLength := rand.Intn(10) + 1
	randomBytes := make([]byte, randomLength)
	rand.Read(randomBytes) 
	payload = append(payload, randomBytes...)
	return &TunnelMessage{
		Type:      MsgTypePing,
		SessionID: 0, // Ping messages don't need a session ID
		SequenceID: 0,
		Payload:   payload,
	}
}

// NewPongMessage creates a PONG message with the received timestamp.
func NewPongMessage(timestamp int64) *TunnelMessage {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(timestamp))
	rand.Seed(time.Now().UnixNano())
	randomLength := rand.Intn(10) + 1
	randomBytes := make([]byte, randomLength)
	rand.Read(randomBytes) 
	payload = append(payload, randomBytes...)
	return &TunnelMessage{
		Type:      MsgTypePong,
		SessionID: 0, // Pong messages don't need a session ID
		SequenceID: 0,
		Payload:   payload,
	}
}

// GetPingTimestamp extracts timestamp from a PING/PONG message.
func GetPingTimestamp(msg *TunnelMessage) (int64, error) {
	if len(msg.Payload) < 8 {
		return 0, fmt.Errorf("invalid ping/pong payload length: %d", len(msg.Payload))
	}
	return int64(binary.BigEndian.Uint64(msg.Payload[:8])), nil
}




func DumpMessage(msg *TunnelMessage) string {
	if len(msg.Payload) <=0 {
		return fmt.Sprintf("invalid payload length: %d", len(msg.Payload))
	}
	
	return fmt.Sprintf("MessageType: %d\nSessionID: %d\nPayloadLength: %d\nPayload: %v",msg.Type, msg.SessionID, len(msg.Payload), msg.Payload)
}