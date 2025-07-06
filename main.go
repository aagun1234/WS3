package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"github.com/aagun1234/ws3/client"
	"github.com/aagun1234/ws3/config"
	"github.com/aagun1234/ws3/server"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) 

	cfg := config.LoadConfig()

	if cfg.Mode == "client" {
		clientApp := client.NewClient(cfg)
		go func() {
			if err := clientApp.Start(); err != nil {
				log.Fatalf("Client error: %v", err)
			}
		}()
		defer clientApp.Stop()
	} else if cfg.Mode == "server" {
		serverApp := server.NewServer(cfg)
		go func() {
			if err := serverApp.Start(); err != nil {
				log.Fatalf("Server error: %v", err)
			}
		}()
		defer serverApp.Stop()
	} else {
		log.Fatalf("Invalid MODE: %s. Must be 'client' or 'server'.", cfg.Mode)
	}

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down program...")
}