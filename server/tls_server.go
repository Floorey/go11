package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
)

func startTLSServer(port int, certFile, keyFile string) {
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Failed to load certificate: ", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), config)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
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

	// Konvertiere die TCP-Verbindung in einen bufio.Reader
	reader := bufio.NewReader(conn)

	// Lese die HTTP-Anfrage des Clients mit bufio.NewReader
	request, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Fehler beim Lesen der Anfrage: %v", err)
		return
	}

	switch request.URL.Path {
	case "/blocks":
		// Hier kannst du die Logik für die /blocks API-Routen hinzufügen
		// Zum Beispiel: Daten von der Blockchain abrufen und an den Client senden
		response := "Blocks at the Blockchain..."
		sendResponse(conn, []byte(response))
	default:
		// Behandle alle anderen Pfade als 404 Not Found
		errorResponse := "404 Not Found"
		sendResponse(conn, []byte(errorResponse))
	}
}

func sendResponse(conn net.Conn, data []byte) {
	_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: " + fmt.Sprint(len(data)) + "\r\n\r\n" + string(data)))
	if err != nil {
		log.Printf("Error sending request: %v", err)
	}
}

func main() {
	port := 8080
	certFile := "server.crt"
	keyFile := "server.key"

	go startTLSServer(port, certFile, keyFile)

	select {}
}
