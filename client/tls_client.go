package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// Disable security checks to allow connecting to the server with self-signed certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	url := "https://localhost:8080/blocks" // Replace "localhost" with the actual server IP if needed

	// Send a GET request to the server
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Failed to send GET request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response body:", err)
		return
	}

	// Print the response body
	fmt.Println("Response from server:")
	fmt.Println(string(body))
}
