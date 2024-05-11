//tls_client.go

package main

import (
	"crypto/tls"
	"log"
)

func main() {
	serverAddr := "localhost:8080"

	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to server.")
}
