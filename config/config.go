package config

/*

{
  "mode": "client",
  "client_proxy_mode": "tcp",
  //"client_proxy_mode": "socks5",
  "client_listen_addr": ":1080",
  "remote_server_addr": "wss://your_vps_ip:8080/ws",
  "forward_target": "127.0.0.1:80",  # 当作为TCP代理时，所有流量都转发到这个目标
  "secret_key": "mysupersecretkey123456789012345",
  "auth_token": "mysecretproxytoken",
  "tunnel_count": 3,
  "ping_interval": 2,
  "log_debug": true,
  "insecure_skip_verify": true
}

{
  "mode": "server",
  "server_listen_addr": ":8080",
  "secret_key": "mysupersecretkey123456789012345",
  "auth_token": "mysecretproxytoken",
  "cert_file": "./certs/server.crt",
  "key_file": "./certs/server.key",
  "log_debug": true
}
*/


import (
	"encoding/json"
	"bytes"
	"log"
	"fmt"
	"os"
	"strconv"
	"strings"
	"flag"
)

// Config represents the application configuration.
// JSON tags are added for easy unmarshaling from a config file.
type Config struct {
	Mode               string `json:"mode"`                 // "client" or "server"
	ClientProxyMode    string `json:"client_proxy_mode"`    // "tcp" or "socks5" (only for client)
	ClientListenAddr   string `json:"client_listen_addr"`   // For client: TCP/SOCKS5 proxy listen address (e.g., ":1080")
	ServerListenAddr   string `json:"server_listen_addr"`   // For server: WebSocket listen address (e.g., ":8080")
	RemoteServerAddr   string `json:"remote_server_addr"`   // For client: Remote WebSocket server address (e.g., "wss://your_vps_ip:8080/ws")
	TargetAddr         string `json:"target_addr"`          // For server: The default/fallback address to forward traffic to if client doesn't specify, OR if server acts as a chained proxy (e.g., "127.0.0.1:1080" for SOCKS5 out)
	ForwardTarget      string `json:"forward_target"`       // For client: The fixed target address for TCP proxy mode (e.g., "google.com:80")
	TunnelCount        int    `json:"tunnel_count"`         // For client (number of WS tunnels)
	SecretKey          string `json:"secret_key"`           // AES-GCM key (32 bytes for AES-256)
	AuthToken          string `json:"auth_token"`           // Pre-shared token for authentication
	PingInterval       int    `json:"ping_interval"`        // Ping interval in seconds for latency measurement
	BaseReconnectDelay int    `json:"base_reconnect_delay"` // Base delay for exponential backoff in seconds
	MaxReconnectDelay  int    `json:"max_reconnect_delay"`  // Maximum delay for exponential backoff in seconds
	CertFile           string `json:"cert_file"`            // Path to TLS certificate file (server)
	KeyFile            string `json:"key_file"`             // Path to TLS private key file (server)
	InsecureSkipVerify bool   `json:"insecure_skip_verify"` // Skip TLS certificate verification (client)
	LogDebug           int   `json:"log_debug"`            // Enable debug logging
	
}

// LoadConfig loads configuration from environment variables and optionally from a JSON file.
// JSON file settings override environment variables.

func parseFlags(cfg *Config) string {
	// 定义命令行参数变量
	var (
		mode               string
		clientProxyMode    string
		clientListenAddr   string
		serverListenAddr   string
		remoteServerAddr   string
		targetAddr         string
		forwardTarget      string
		tunnelCount        int
		secretKey          string
		authToken          string
		pingInterval       int
		baseReconnectDelay int
		maxReconnectDelay  int
		certFile           string
		keyFile            string
		insecureSkipVerify bool
		logDebug           int
		cfgfile            string
	)

	// 注册命令行参数
	flag.StringVar(&cfgfile, "cfg", "", "cfg file")
	flag.StringVar(&mode, "mode", "", "Operation mode: 'client' or 'server'")
	flag.StringVar(&clientProxyMode, "client-proxy-mode", "", "Client proxy mode: 'tcp' or 'socks5'")
	flag.StringVar(&clientListenAddr, "client-listen-addr", "", "Client proxy listen address")
	flag.StringVar(&serverListenAddr, "server-listen-addr", "", "Server WebSocket listen address")
	flag.StringVar(&remoteServerAddr, "remote-server-addr", "", "Remote WebSocket server address (client mode)")
	flag.StringVar(&targetAddr, "target-addr", "", "Default target address for server mode")
	flag.StringVar(&forwardTarget, "forward-target", "", "Fixed target address for TCP proxy mode")
	flag.IntVar(&tunnelCount, "tunnel-count", 0, "Number of WebSocket tunnels (client mode)")
	flag.StringVar(&secretKey, "secret-key", "", "AES-GCM key (32 bytes for AES-256)")
	flag.StringVar(&authToken, "auth-token", "", "Pre-shared token for authentication")
	flag.IntVar(&pingInterval, "ping-interval", 30, "Ping interval in seconds")
	flag.IntVar(&baseReconnectDelay, "base-reconnect-delay", 0, "Base reconnect delay in seconds")
	flag.IntVar(&maxReconnectDelay, "max-reconnect-delay", 0, "Maximum reconnect delay in seconds")
	flag.StringVar(&certFile, "cert-file", "", "Path to TLS certificate file")
	flag.StringVar(&keyFile, "key-file", "", "Path to TLS private key file")
	flag.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification")
	flag.IntVar(&logDebug, "log-debug", 0, "Enable debug logging")

	// 自定义用法信息
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample (client):\n  %s -mode client -remote-server-addr wss://example.com:8080/ws -secret-key '32bytekey...'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nExample (server):\n  %s -mode server -target-addr 127.0.0.1:1080 -secret-key '32bytekey...'\n", os.Args[0])
	}

	flag.Parse()

	// 只覆盖命令行中指定的参数
	if mode != "" {
		cfg.Mode = mode
	}
	if clientProxyMode != "" {
		cfg.ClientProxyMode = clientProxyMode
	}
	if clientListenAddr != "" {
		cfg.ClientListenAddr = clientListenAddr
	}
	if serverListenAddr != "" {
		cfg.ServerListenAddr = serverListenAddr
	}
	if remoteServerAddr != "" {
		cfg.RemoteServerAddr = remoteServerAddr
	}
	if targetAddr != "" {
		cfg.TargetAddr = targetAddr
	}
	if forwardTarget != "" {
		cfg.ForwardTarget = forwardTarget
	}
	if tunnelCount > 0 {
		cfg.TunnelCount = tunnelCount
	}
	if secretKey != "" {
		cfg.SecretKey = secretKey
	}
	if authToken != "" {
		cfg.AuthToken = authToken
	}
	if pingInterval > 0 {
		cfg.PingInterval = pingInterval
	}
	if baseReconnectDelay > 0 {
		cfg.BaseReconnectDelay = baseReconnectDelay
	}
	if maxReconnectDelay > 0 {
		cfg.MaxReconnectDelay = maxReconnectDelay
	}
	if certFile != "" {
		cfg.CertFile = certFile
	}
	if keyFile != "" {
		cfg.KeyFile = keyFile
	}
	cfg.InsecureSkipVerify = insecureSkipVerify
	
	cfg.LogDebug = logDebug
	 
	
	return cfgfile
}


func LoadConfig() *Config {
	cfg := &Config{} // Start with an empty config struct

	// 1. Load from Environment Variables
	cfg.Mode = os.Getenv("MODE")
	cfg.ClientProxyMode = os.Getenv("CLIENT_PROXY_MODE")
	cfg.ClientListenAddr = os.Getenv("CLIENT_LISTEN_ADDR")
	cfg.ServerListenAddr = os.Getenv("SERVER_LISTEN_ADDR")
	cfg.RemoteServerAddr = os.Getenv("REMOTE_SERVER_ADDR")
	cfg.TargetAddr = os.Getenv("TARGET_ADDR")
	cfg.ForwardTarget = os.Getenv("FORWARD_TARGET")
	cfg.SecretKey = os.Getenv("SECRET_KEY")
	cfg.AuthToken = os.Getenv("AUTH_TOKEN")
	cfg.CertFile = os.Getenv("CERT_FILE")
	cfg.KeyFile = os.Getenv("KEY_FILE")

	// Parse boolean and integer environment variables
	if os.Getenv("INSECURE_SKIP_VERIFY") == "true" {
		cfg.InsecureSkipVerify = true
	}
	if dbg1 := os.Getenv("LOG_DEBUG"); dbg1!="" {
		if dbg, err := strconv.Atoi(dbg1); err == nil {
			cfg.LogDebug = dbg
		}
	}

	if tc := os.Getenv("TUNNEL_COUNT"); tc != "" {
		if count, err := strconv.Atoi(tc); err == nil {
			cfg.TunnelCount = count
		}
	}
	if pi := os.Getenv("PING_INTERVAL"); pi != "" {
		if interval, err := strconv.Atoi(pi); err == nil {
			cfg.PingInterval = interval
		}
	}
	if brd := os.Getenv("BASE_RECONNECT_DELAY"); brd != "" {
		if delay, err := strconv.Atoi(brd); err == nil {
			cfg.BaseReconnectDelay = delay
		}
	}
	if mrd := os.Getenv("MAX_RECONNECT_DELAY"); mrd != "" {
		if delay, err := strconv.Atoi(mrd); err == nil {
			cfg.MaxReconnectDelay = delay
		}
	}

	// Set default values if not provided by env vars
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 30
	}
	if cfg.BaseReconnectDelay == 0 {
		cfg.BaseReconnectDelay = 1
	}
	if cfg.MaxReconnectDelay == 0 {
		cfg.MaxReconnectDelay = 60
	}
	if cfg.TunnelCount == 0 && cfg.Mode == "client" { // Default for client
		cfg.TunnelCount = 1
	}

	// 2. Load from JSON Config File if CONFIG_FILE env var is set
	configFilePath := ""
	if configFilePath = os.Getenv("CONFIG_FILE"); configFilePath == "" {
		
		configFilePath = parseFlags(cfg)
	}
		

    if	configFilePath != "" {
		log.Printf("Loading configuration from file: %s", configFilePath)
		fileData, err := os.ReadFile(configFilePath)
		if err != nil {
			log.Fatalf("Failed to read config file %s: %v", configFilePath, err)
		}

		var fileCfg Config // Create a temporary config struct for file content
		if err := json.Unmarshal(fileData, &fileCfg); err != nil {
			log.Fatalf("Failed to parse config file %s: %v", configFilePath, err)
		}

		// Merge fileCfg into cfg, overriding env vars
		// Override string fields if not empty in fileCfg
		if fileCfg.Mode != "" {
			cfg.Mode = fileCfg.Mode
		}
		if fileCfg.ClientProxyMode != "" {
			cfg.ClientProxyMode = fileCfg.ClientProxyMode
		}
		if fileCfg.ClientListenAddr != "" {
			cfg.ClientListenAddr = fileCfg.ClientListenAddr
		}
		if fileCfg.ServerListenAddr != "" {
			cfg.ServerListenAddr = fileCfg.ServerListenAddr
		}
		if fileCfg.RemoteServerAddr != "" {
			cfg.RemoteServerAddr = fileCfg.RemoteServerAddr
		}
		if fileCfg.TargetAddr != "" {
			cfg.TargetAddr = fileCfg.TargetAddr
		}
		if fileCfg.ForwardTarget != "" {
			cfg.ForwardTarget = fileCfg.ForwardTarget
		}
		if fileCfg.SecretKey != "" {
			cfg.SecretKey = fileCfg.SecretKey
		}
		if fileCfg.AuthToken != "" {
			cfg.AuthToken = fileCfg.AuthToken
		}
		if fileCfg.CertFile != "" {
			cfg.CertFile = fileCfg.CertFile
		}
		if fileCfg.KeyFile != "" {
			cfg.KeyFile = fileCfg.KeyFile
		}

		// Override int fields if not zero in fileCfg (unless zero is a valid config value)
		// For int, assume non-zero in JSON means it's explicitly set and overrides.
		if fileCfg.TunnelCount != 0 {
			cfg.TunnelCount = fileCfg.TunnelCount
		}
		if fileCfg.PingInterval != 0 {
			cfg.PingInterval = fileCfg.PingInterval
		}
		if fileCfg.BaseReconnectDelay != 0 {
			cfg.BaseReconnectDelay = fileCfg.BaseReconnectDelay
		}
		if fileCfg.MaxReconnectDelay != 0 {
			cfg.MaxReconnectDelay = fileCfg.MaxReconnectDelay
		}

		// Override bool fields if explicitly set in JSON (true or false)
		// This requires checking if the key actually exists in the JSON.
		// A common robust way is to use pointers *bool or use raw JSON unmarshaling.
		// For simplicity, directly assign assuming JSON true/false is desired override.
		// If you need to distinguish "not present" from "false", use *bool for `InsecureSkipVerify` and `LogDebug` in `Config` struct.
		// For now, if the field is present and parsed from JSON, it overrides.
		if bytes.Contains(fileData, []byte(`"insecure_skip_verify":`)) { // Simple check if key exists
			cfg.InsecureSkipVerify = fileCfg.InsecureSkipVerify
		}
		if bytes.Contains(fileData, []byte(`"log_debug":`)) { // Simple check if key exists
			cfg.LogDebug = fileCfg.LogDebug
		}
	}

	// 3. Final Validation and Defaults
	if cfg.Mode == "" {
		log.Fatal("Configuration error: MODE is required (either via env or config file).")
	}
	if cfg.SecretKey == "" {
		log.Fatal("Configuration error: SECRET_KEY is required for encryption. Must be 32 bytes for AES-256.")
	}
	if len(cfg.SecretKey) != 32 {
		log.Fatalf("Configuration error: SECRET_KEY must be 32 bytes long for AES-256, got %d bytes.", len(cfg.SecretKey))
	}
	if cfg.AuthToken == "" {
		log.Fatal("Configuration error: AUTH_TOKEN is required for client/server authentication.")
	}

	if cfg.Mode == "client" {
		if cfg.ClientListenAddr == "" {
			log.Fatal("Configuration error: CLIENT_LISTEN_ADDR is required for client mode.")
		}
		if cfg.RemoteServerAddr == "" {
			log.Fatal("Configuration error: REMOTE_SERVER_ADDR (WebSocket server address) is required for client mode.")
		}
		if cfg.ClientProxyMode == "" {
			log.Println("Warning: CLIENT_PROXY_MODE not specified, defaulting to 'tcp'.")
			cfg.ClientProxyMode = "tcp" // Default client mode
		}
		if cfg.ClientProxyMode != "tcp" && cfg.ClientProxyMode != "socks5" {
			log.Fatalf("Configuration error: Invalid CLIENT_PROXY_MODE: %s. Must be 'tcp' or 'socks5'.", cfg.ClientProxyMode)
		}
		if cfg.ClientProxyMode == "tcp" && cfg.ForwardTarget == "" {
			log.Fatal("Configuration error: FORWARD_TARGET is required for client in 'tcp' proxy mode.")
		}
	} else if cfg.Mode == "server" {
		if cfg.ServerListenAddr == "" {
			log.Fatal("Configuration error: SERVER_LISTEN_ADDR (WebSocket listen address) is required for server mode.")
		}
		// In this universal mode, TargetAddr for server is optional.
		// If client is SOCKS5, it specifies the target. If client is TCP, it specifies the target.
		// TargetAddr in server might be used if server acts as a chained proxy (e.g., to a local SS).
		// For simplicity, we assume server will dial directly to client's requested target.
		// If TargetAddr is set, server could use it to chain (more complex).
		// For now, it's not strictly required here unless for a specific chained proxy setup.

		// Check for TLS config if listening on a public interface
		if strings.HasPrefix(cfg.ServerListenAddr, ":") || strings.HasPrefix(cfg.ServerListenAddr, "0.0.0.0") {
			if cfg.CertFile == "" || cfg.KeyFile == "" {
				log.Println("Configuration WARNING: For server mode listening on a public address, CERT_FILE and KEY_FILE are required for WSS (secure WebSocket).")
			}
		}
	} else {
		log.Fatalf("Configuration error: Invalid MODE: %s. Must be 'client' or 'server'.", cfg.Mode)
	}

	return cfg
}