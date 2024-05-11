//tls_server.go

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

func startTLSServer(port int, certFile, keyFile string) {
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), config)
	if err != nil {
		log.Fatalf("Failed to start TLS server: %v", err)
	}
	defer listener.Close()

	log.Printf("TLS server started on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Println("Client connected.")
}
func main() {
	port := 8080
	certFile := "server.crt"
	keyFile := "server.key"

	go startTLSServer(port, certFile, keyFile)
}
