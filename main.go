package main

//go:generate goimports -w .

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/unidoc/unipdf/v3/extractor"
	"github.com/unidoc/unipdf/v3/model"
)

type Block struct {
	ID           int
	Data         string
	PreviousHash string
	Timestamp    time.Time
	Hash         string
	Previous     *Block
	Signature    []byte
}

type Blockchain struct {
	Head   *Block
	mu     sync.Mutex
	Blocks []*Block // Speichern aller Blöcke für den einfachen Zugriff
	DB     *sql.DB  // Verweis auf die Datenbank
}
type Peer struct {
	ID   int
	IP   string
	Port int
}
type Network struct {
	Peers []*Peer
	mu    sync.Mutex
}
type Transaction struct {
	Sender    string
	Recipient string
	Amount    float64
	Fee       float64
}

// SendMessageToPeer sendet eine Nachricht von einem Peer an einen anderen.
func (n *Network) SendMessageToPeer(senderID int, receiverID int, message string) error {
	sender := n.GetPeerByID(senderID)
	if sender == nil {
		return fmt.Errorf("Sender with ID %d not found", senderID)
	}

	receiver := n.GetPeerByID(receiverID)
	if receiver == nil {
		return fmt.Errorf("Receiver with ID %d not found", receiverID)
	}

	// Simuliere den Nachrichtenversand
	fmt.Printf("Message sent from Peer %d to Peer %d: %s\n", senderID, receiverID, message)
	return nil
}

func CreateTransaction(sender, recipient string, amount, fee float64) *Transaction {
	return &Transaction{
		Sender:    sender,
		Recipient: recipient,
		Amount:    amount,
		Fee:       fee,
	}
}
func ValidateTransaction(tx *Transaction, senderBalance float64) bool {
	if senderBalance < tx.Amount+tx.Fee {
		return false
	}
	return true
}
func Executetransaction(tx *Transaction, senderBalance *float64, recipientBalance *float64) {
	*senderBalance -= tx.Amount + tx.Fee
	*recipientBalance += tx.Amount
}
func CalculateBalance(transactions []*Transaction, account string, initialBalance float64) float64 {
	balance := initialBalance
	for _, tx := range transactions {
		if tx.Sender == account {
			balance -= tx.Amount + tx.Fee
		}
		if tx.Recipient == account {
			balance += tx.Amount
		}
	}
	return balance
}

func isValidSHA256Proof(hash string) bool {
	requiredLeadingZeros := 4

	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return false
	}
	for i := 0; i < requiredLeadingZeros/2; i++ {
		if hashBytes[i] != 0 {
			return false
		}
	}
	return true
}

func NewNetwork() *Network {
	return &Network{
		Peers: []*Peer{},
	}
}

// add new peer to network
func (n *Network) AddPeer(peer *Peer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Peers = append(n.Peers, peer)
}
func (n *Network) PrintPeers() {
	n.mu.Lock()
	defer n.mu.Unlock()
	fmt.Println("List of Peers:")
	for _, peer := range n.Peers {
		fmt.Printf("ID: %d, IP: %s, Port: %d\n", peer.ID, peer.IP, peer.Port)
	}
}

func NewBlockchain(db *sql.DB) *Blockchain {
	// Verbindung zur SQLite-Datenbank herstellen
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS blocks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		data TEXT,
		previous_hash TEXT,
		timestamp TEXT,
		hash TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// Beispielblock (Genesis-Block) erstellen und in die Datenbank einfügen
	genesisBlock := &Block{
		Data:         "Genesis Block",
		PreviousHash: "",
		Timestamp:    time.Now(),
		Hash:         calculateHash("Genesis Block", ""),
	}
	err = insertBlock(db, genesisBlock)
	if err != nil {
		log.Fatal(err)
	}

	return &Blockchain{
		Head:   genesisBlock,
		Blocks: []*Block{genesisBlock},
		DB:     db,
	}
}

// Funktion zum Einfügen eines Blocks in die Datenbank
func insertBlock(db *sql.DB, block *Block) error {
	_, err := db.Exec(`INSERT INTO blocks (data, previous_hash, timestamp, hash)
	VALUES (?, ?, ?, ?)`, block.Data, block.PreviousHash, block.Timestamp, block.Hash)
	return err
}

func calculateHash(data string, previousHash string) string {
	hashBytes := sha256.Sum256([]byte(data + previousHash))
	return hex.EncodeToString(hashBytes[:])
}
func isValidProof(hash string) bool {
	return strings.HasPrefix(hash, "0000")
}
func (chain *Blockchain) ValidateBlock(block *Block) bool {
	// Überprüfen, ob der Blockhash gültig ist
	if !isValidSHA256Proof(block.Hash) {
		return false
	}

	// Überprüfen, ob der Hash des vorherigen Blocks mit dem PreviousHash des aktuellen Blocks übereinstimmt
	if block.Previous != nil && block.Previous.Hash != block.PreviousHash {
		return false
	}

	// Weitere Validierungsschritte hier hinzufügen, falls erforderlich...

	return true
}

func (chain *Blockchain) AddBlock(data string) {
	// Vorherigen Block erhalten
	previousBlock := chain.Blocks[len(chain.Blocks)-1]

	// Neuen Block erstellen mit den übergebenen Daten
	newBlock := &Block{
		Data:         data, // Übergebene Daten
		PreviousHash: previousBlock.Hash,
		Timestamp:    time.Now(),
		Hash:         calculateHash(data, previousBlock.Hash),
	}

	// Block in die Datenbank einfügen, wenn die Datenbank vorhanden ist
	if chain.DB != nil {
		err := insertBlock(chain.DB, newBlock)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Neuen Block zur Blockchain hinzufügen
	chain.Blocks = append(chain.Blocks, newBlock)
}

func (chain *Blockchain) PrintBlockchain() {
	chain.mu.Lock()
	defer chain.mu.Unlock()

	currentBlock := chain.Head
	for currentBlock != nil {
		fmt.Printf("Data: %s\nPrevious Hash: %s\nTimestamp: %s\nHash: %s\n\n",
			currentBlock.Data, currentBlock.PreviousHash, currentBlock.Timestamp, currentBlock.Hash)
		currentBlock = currentBlock.Previous
	}
}

func (chain *Blockchain) LogHashesToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	currentBlock := chain.Head
	for currentBlock != nil {
		_, err := writer.WriteString(fmt.Sprintf("Data: %s\nPrevious Hash: %s\nTimestamp: %s\nHash: %s\n\n",
			currentBlock.Data, currentBlock.PreviousHash, currentBlock.Timestamp, currentBlock.Hash))
		if err != nil {
			return err
		}
		currentBlock = currentBlock.Previous
	}

	return nil
}

func ReadText(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var content strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		content.WriteString(scanner.Text())
		content.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return content.String(), nil
}

func ReadCSV(filename string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err

	}
	return records, nil
}

func ReadJSON(filename string, v interface{}) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&v); err != nil {
		return err
	}
	return nil
}

func ReadTextFromPDF(filename string) (string, error) {
	// Öffne die PDF-Datei.
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Öffne die PDF-Datei als ein PDF-Modelldokument.
	pdfReader, err := model.NewPdfReader(f)
	if err != nil {
		return "", err
	}

	// Extrahiere den Text von jeder Seite der PDF-Datei.
	var textBuilder strings.Builder
	numPages, err := pdfReader.GetNumPages()
	if err != nil {
		return "", err
	}
	for pageNum := 1; pageNum <= numPages; pageNum++ {
		page, err := pdfReader.GetPage(pageNum)
		if err != nil {
			return "", err
		}

		// Extrahiere den Text von der aktuellen Seite.
		pageExtractor, err := extractor.New(page)
		if err != nil {
			return "", err
		}
		pageText, err := pageExtractor.ExtractText()
		if err != nil {
			return "", err
		}

		// Füge den extrahierten Text zur Gesamtausgabe hinzu.
		textBuilder.WriteString(pageText)
	}

	return textBuilder.String(), nil
}
func PrintBlockByIndex(chain *Blockchain, index int) {
	if index < 0 || index >= len(chain.Blocks) {
		fmt.Println("Invalid index. Please enter a valid index.")
		return
	}
	block := chain.Blocks[index]
	fmt.Printf("Block at index %d:\n", index)
	fmt.Printf("Data: %s\nPrevious Hash: %s\nTimestamp: %s\nHash: %s\n\n",
		block.Data, block.PreviousHash, block.Timestamp, block.Hash)

	// Ausgabe des vorherigen Hash-Werts, wenn verfügbar
	if block.Previous != nil {
		fmt.Printf("Previous Hash: %s\n", block.Previous.Hash)
	} else {
		fmt.Println("This is the genesis block, so there is no previous hash.")
	}
}
func TestPeers(network *Network) {
	fmt.Println("Testing Peers...")
	for _, peer := range network.Peers {
		go func(peer *Peer) {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.Port), 5*time.Second)
			if err != nil {
				fmt.Printf("Failed to connect to peer %s:%d\n", peer.IP, peer.Port)
				return
			}
			defer conn.Close()

			fmt.Printf("Connected to peer %s:%d\n", peer.IP, peer.Port)

		}(peer)
	}
}
func SyncBlockchainWithPeers(chain *Blockchain, network *Network) {
	for _, peer := range network.Peers {
		go func(peer *Peer) {
			// Verbindung zum Peer herstellen
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.Port), 5*time.Second)
			if err != nil {
				fmt.Printf("Failed to connect to peer %s:%d\n", peer.IP, peer.Port)
				return
			}
			defer conn.Close()

			// Synchronisieren der Blockchain mit dem Peer
			encoder := json.NewEncoder(conn)
			decoder := json.NewDecoder(conn)

			// Anfrage für die Blockchain des Peers senden
			err = encoder.Encode("get_blocks")
			if err != nil {
				fmt.Printf("Error sending get_blocks request to peer %s:%d: %s\n", peer.IP, peer.Port, err)
				return
			}

			// Antwort vom Peer empfangen
			var peerBlocks []*Block
			err = decoder.Decode(&peerBlocks)
			if err != nil {
				fmt.Printf("Error receiving blocks from peer %s:%d: %s\n", peer.IP, peer.Port, err)
				return
			}

			// Neue Blöcke in die lokale Blockchain einfügen
			for _, block := range peerBlocks {
				if chain.Head == nil || block.ID > chain.Head.ID {
					// Überprüfen, ob der Block gültig ist, bevor er eingefügt wird
					if chain.ValidateBlock(block) {
						chain.Blocks = append(chain.Blocks, block)
						chain.Head = block
						fmt.Printf("Added new block from peer %s:%d\n", peer.IP, peer.Port)
					} else {
						fmt.Printf("Received invalid block from peer %s:%d, block ID: %d\n", peer.IP, peer.Port, block.ID)
					}
				}
			}
		}(peer)
	}
}

func loadImageFromJPEG(filename string) ([]byte, error) {
	imageData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return imageData, nil
}

// RetrieveBlocksFromDB ruft alle Blöcke aus der Datenbank ab und gibt sie zurück.
func RetrieveBlocksFromDB(db *sql.DB) ([]*Block, error) {
	rows, err := db.Query("SELECT id, data, previous_hash, timestamp, hash FROM blocks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []*Block
	for rows.Next() {
		var id int
		var data, previousHash, timestampStr, hash string
		if err := rows.Scan(&id, &data, &previousHash, &timestampStr, &hash); err != nil {
			return nil, err
		}
		timestamp, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", timestampStr)
		if err != nil {
			return nil, err
		}
		block := &Block{
			ID:           id,
			Data:         data,
			PreviousHash: previousHash,
			Timestamp:    timestamp,
			Hash:         hash,
		}
		blocks = append(blocks, block)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return blocks, nil
}

// VerifyBlockIDs überprüft, ob die IDs der Blöcke eindeutig sind und ob es keine doppelten Hashes gibt.
func VerifyBlockIDs(blocks []*Block) error {
	existingIDs := make(map[int]bool)
	existingHashes := make(map[string]bool)

	for _, block := range blocks {
		// Überprüfen, ob die ID bereits existiert
		if existingIDs[block.ID] {
			return fmt.Errorf("duplicate block ID: %d", block.ID)
		}
		existingIDs[block.ID] = true

		// Überprüfen, ob der Hash bereits existiert
		if existingHashes[block.Hash] {
			return fmt.Errorf("duplicate block hash: %s", block.Hash)
		}
		existingHashes[block.Hash] = true
	}

	return nil
}
func LoadBlockFromDB(db *sql.DB, id int) (*Block, error) {
	var data, previousHash, timestampStr, hash string
	err := db.QueryRow("SELECT data, previous_hash, timestamp, hash FROM blocks WHERE id=?", id).
		Scan(&data, &previousHash, &timestampStr, &hash)
	if err != nil {
		return nil, err
	}
	timestamp, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", timestampStr)
	if err != nil {
		return nil, err
	}
	return &Block{
		ID:           id,
		Data:         data,
		PreviousHash: previousHash,
		Timestamp:    timestamp,
		Hash:         hash,
	}, nil
}
func displayImageFromBlock(block *Block) error {
	if block.Data == "" {
		return fmt.Errorf("Block data is empty.")
	}
	imageData := []byte(block.Data)
	img, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return err

	}
	fmt.Println("Displaying image from block:")
	err = jpeg.Encode(os.Stdout, img, nil)
	if err != nil {
		return err
	}
	return nil
}
func generateUserKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
func signData(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Daten mit dem privaten Schlüssel signieren
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, data)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
func signBlock(block *Block, privatKey *rsa.PrivateKey) error {
	blockData := []byte(fmt.Sprintf("%v", block))

	signature, err := signData(blockData, privatKey)
	if err != nil {
		return err
	}
	block.Signature = signature

	return nil
}
func AddSignedBlockWithUserKey(chain *Blockchain, data string, privateKey *rsa.PrivateKey) error {
	// Datenkanal erstellen
	dataChan := make(chan *Block)

	// Go-Routine starten, um Daten in den Kanal zu senden
	go func() {
		// Neuen Block erstellen
		previousBlock := chain.Blocks[len(chain.Blocks)-1]
		newBlock := &Block{
			Data:         data,
			PreviousHash: previousBlock.Hash,
			Timestamp:    time.Now(),
			Hash:         calculateHash(data, previousBlock.Hash),
		}

		// Block signieren
		err := signBlock(newBlock, privateKey)
		if err != nil {
			fmt.Println("Fehler beim Signieren des Blocks:", err)
			return
		}

		// Block zur Blockchain hinzufügen
		dataChan <- newBlock
	}()

	// Daten aus dem Kanal lesen und Block mit Signatur zur Blockchain hinzufügen
	go func() {
		for newBlock := range dataChan {
			// Block in die Datenbank einfügen, wenn die Datenbank vorhanden ist
			if chain.DB != nil {
				err := insertBlock(chain.DB, newBlock)
				if err != nil {
					fmt.Println("Fehler beim Einfügen des Blocks in die Datenbank:", err)
				}
			}

			// Neuen Block zur Blockchain hinzufügen
			chain.Blocks = append(chain.Blocks, newBlock)
		}
	}()

	return nil
}
func EncryptData(data string, key []byte) ([]byte, error) {
	plaintext := []byte(data)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}
func TrackBlockchainFlow(chain *Blockchain) {
	fmt.Println("Tracking Blockchain Flow:")

	go func() {
		for {
			time.Sleep(5 * time.Second)
			currentBlockCount := len(chain.Blocks)
			if currentBlockCount > 1 {
				fmt.Printf("New block added! Total blocks: %d\n", currentBlockCount)
			}
		}
	}()
	fmt.Println("Press 'q' to stop tracking.")
	reader := bufio.NewReader(os.Stdin)
	for {
		char, _, err := reader.ReadRune()
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}
		if char == 'q' || char == 'Q' {
			fmt.Println("Stopped tracking Blockchain Flow.")
			break
		}
	}
}
func LogBlockchain(chain *Blockchain, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err

	}
	defer file.Close()

	for _, block := range chain.Blocks {
		_, err := file.WriteString(fmt.Sprintf("Block ID; %d\n"))
		if err != nil {
			return err
		}
		_, err = file.WriteString(fmt.Sprintf("Data: %s\n", block.Data))
		if err != nil {
			return err
		}
		_, err = file.WriteString(fmt.Sprintf("Tiemstamp: %s\n", block.Timestamp))
		if err != nil {
			return err
		}
		_, err = file.WriteString(fmt.Sprintf("Pervious Hash: %s\n", block.PreviousHash))
		if err != nil {
			return err
		}
		_, err = file.WriteString(fmt.Sprintf("Hash: %s\n", block.Hash))
		if err != nil {
			return err
		}
		_, err = file.WriteString("\n")
		if err != nil {
			return err
		}
	}
	return nil
}
func RunBlockchainAPI(chain *Blockchain, network *Network, db *sql.DB) {
	http.HandleFunc("/blocks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			blocksJSON, err := json.Marshal(chain.Blocks)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "aplication/json")
			w.Write(blocksJSON)
		case http.MethodPost:
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			data := string(body)
			chain.AddBlock(data)

			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Block added successfully"))
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Logik zum Abrufen der Peers und Senden als JSON-Antwort
			peersJSON, err := json.Marshal(network.Peers)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(peersJSON)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/blocks/log", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// Logik zum Protokollieren der Blockchain in eine Datei
			filename := r.FormValue("filename")
			err := LogBlockchain(chain, filename)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Blockchain logged to file successfully"))
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	port := ":8080" // Ändern Sie den Port nach Bedarf
	fmt.Printf("Starting blockchain API server on port %s...\n", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("Server error:", err)
	}
}
func (n *Network) GetPeerByID(id int) *Peer {
	for _, peer := range n.Peers {
		if peer.ID == id {
			return peer
		}
	}
	return nil
}
func LogActivity(activity string) error {
	file, err := os.OpenFile("activity.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	logLine := fmt.Sprintf("[%s] %s\n", time.Now().Format(time.RFC3339), activity)
	_, err = file.WriteString(logLine)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	db, err := sql.Open("sqlite3", "./blockchain.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	chain := NewBlockchain(db)

	network := NewNetwork()

	peer1 := &Peer{ID: 1, IP: "192.168.0.1", Port: 3000}
	peer2 := &Peer{ID: 2, IP: "192.168.0.2", Port: 4000}

	network.AddPeer(peer1)
	network.AddPeer(peer2)

	LogActivity("Peers added to network.")

	network.PrintPeers()

	TrackBlockchainFlow(chain)

	for {
		fmt.Println("Choose an option:")
		fmt.Println("1. Insert Text")
		fmt.Println("2. Save Text in a Block")
		fmt.Println("3. Print current Block")
		fmt.Println("4. Log Hashes to File")
		fmt.Println("5. Read Text from File")
		fmt.Println("6. Read CSV from File")
		fmt.Println("7. Read JSON from File")
		fmt.Println("8. Read Text from PDF")
		fmt.Println("9. Validate Block")
		fmt.Println("10. Print specific Block")
		fmt.Println("11. Toggle Block Saving to Database")
		fmt.Println("12. Read jpeg-image.")
		fmt.Println("13. Load blocks from DB")
		fmt.Println("14. Load and Display Images")
		fmt.Println("15. Encrypt Text")
		fmt.Println("16. Log-Blockchain")
		fmt.Println("17. Comunicate between Peers")
		fmt.Println("18. Exit")

		reader := bufio.NewReader(os.Stdin)
		optionStr, _ := reader.ReadString('\n')
		optionStr = strings.TrimSpace(optionStr)

		option, err := strconv.Atoi(optionStr)
		if err != nil {
			fmt.Println("Invalid option. Please enter a number!")
			continue
		}
		switch option {
		case 1:
			fmt.Print("Enter a text: ")
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			chain.AddBlock(text)
			fmt.Println("Text inserted and saved in a block!")
			LogActivity("text added to Blockchain")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 2:
			fmt.Print("Enter text to save in a block: ")
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			chain.AddBlock(text)
			fmt.Println("Text saved in a block.")
			LogActivity("Text entered to Block.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 3:
			fmt.Println("Current Block:")
			chain.PrintBlockchain()
			LogActivity("Block printed.")
			if err != nil {
				fmt.Printf("Error printing the Block.")
			}
		case 4:
			fmt.Print("Enter filename to save hashes: ")
			filename, _ := reader.ReadString('\n')
			filename = strings.TrimSpace(filename)
			err := chain.LogHashesToFile(filename)
			if err != nil {
				fmt.Printf("Error logging hashes to file: %s\n", err)
			} else {
				fmt.Println("Hashes logged to file successfully.")
			}
			LogActivity("Hashes saved!")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 5:
			fmt.Print("Enter filename to read text from: ")
			filename, _ := reader.ReadString('\n')
			filename = strings.TrimSpace(filename)
			textCh := make(chan string)
			errCh := make(chan error)
			go func() {
				text, err := ReadText(filename)
				if err != nil {
					errCh <- err
				} else {
					textCh <- text
				}
			}()
			select {
			case text := <-textCh:
				chain.AddBlock(text)
				fmt.Println("Text read from file and saved in a block:", text)
			case err := <-errCh:
				fmt.Printf("Error reading text from file: %s\n", err)
			}
			LogActivity("Filename read from a Block")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 6:
			fmt.Print("Enter filename to read CSV from: ")
			filename, _ := reader.ReadString('\n')
			filename = strings.TrimSpace(filename)
			recordsCh := make(chan [][]string)
			errCh := make(chan error)

			go func() {
				records, err := ReadCSV(filename)
				if err != nil {
					errCh <- err
				} else {
					recordsCh <- records
				}
			}()
			select {
			case records := <-recordsCh:
				for _, record := range records {
					text := strings.Join(record, ", ")
					chain.AddBlock(text)
				}
				fmt.Println("CSV read from file and saved in blocks:", records)
			case err := <-errCh:
				fmt.Printf("Error reading CSV from file: %s\n", err)
			}
			LogActivity("CSV file read from Block.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 7:
			fmt.Print("Enter filename to read JSON from: ")
			filename, _ := reader.ReadString('\n')
			filename = strings.TrimSpace(filename)
			var jsonData interface{}
			errCh := make(chan error)
			go func() {
				err := ReadJSON(filename, &jsonData)
				if err != nil {
					errCh <- err
				}
			}()
			select {
			case err := <-errCh:
				fmt.Printf("Error reading JSON from file: %s\n", err)
			default:
				jsonText, _ := json.Marshal(jsonData)
				chain.AddBlock(string(jsonText))
				fmt.Println("JSON read from file and saved in a block:", jsonData)
			}
			LogActivity("JASON read from Block-file.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 8:
			fmt.Print("Enter filename to read PDF from: ")
			filename, _ := reader.ReadString('\n')
			filename = strings.TrimSpace(filename)
			text, err := ReadTextFromPDF(filename)
			if err != nil {
				fmt.Printf("Error reading text from PDF file: %s\n", err)
			} else {
				chain.AddBlock(text) // Text als Block an die Blockchain anhängen
				fmt.Println("Text read from PDF file and saved in a block:", text)
			}
			LogActivity("PDF file read from Block.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 9:
			// Code für Option 9 (Block validieren)
			fmt.Println("Enter index of the block to validate: ")
			indexStr, _ := reader.ReadString('\n')
			indexStr = strings.TrimSpace(indexStr)
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				fmt.Println("Invalid index. Please enter a number!")
				continue
			}
			if index < 0 || index >= len(chain.Blocks) {
				fmt.Println("Invalid index. Please enter a valid index!")
				continue
			}
			block := chain.Blocks[index]
			valid := chain.ValidateBlock(block)
			if valid {
				fmt.Println("Block is valid!")
			} else {
				fmt.Println("Block is not valid!")
			}
			LogActivity("Block validated!")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 10:
			fmt.Println("Enter index of the block to display:")
			indexStr, _ := reader.ReadString('\n')
			indexStr = strings.TrimSpace(indexStr)
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				fmt.Println("Invalid index. Please enter a number!")
				continue
			}
			PrintBlockByIndex(chain, index)

			LogActivity("Display Block!")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 11:
			if chain.DB != nil {
				fmt.Println("Blockchain saving to database is currently enabled. Disabling...")
				chain.DB = nil
			} else {
				fmt.Println("Blockchain saving to database is currently disabled. Enabling...")
				chain.DB = db
			}
			LogActivity("Blcokchain saved to DB.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 12:
			fmt.Print("Enter path to JPEG image: ")
			imagePath, _ := reader.ReadString('\n')
			imagePath = strings.TrimSpace(imagePath)
			imageData, err := loadImageFromJPEG(imagePath)
			if err != nil {
				fmt.Printf("Error loading image: %s\n", err)
				continue
			}
			// Konvertieren Sie die Bilddaten in eine Zeichenfolge und speichern Sie sie in einem Block
			imageStr := string(imageData)
			chain.AddBlock(imageStr)
			fmt.Println("Image saved in a block.")

			LogActivity("Image seved into Block.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}

		case 13:
			blocks, err := RetrieveBlocksFromDB(db)
			if err != nil {
				fmt.Printf("Error retrieving blocks from database: %s\n", err)
				continue
			}
			fmt.Println("Blocks loaded successfully from the database:")
			for _, block := range blocks {
				fmt.Printf("ID: %d, Data: %s, Timestamp: %s\n", block.ID, block.Data, block.Timestamp)
			}
			LogActivity("Read Blocks from DB.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 14:
			fmt.Println("Enter the ID of the block to load and display the image:")
			idStr, _ := reader.ReadString('\n')
			idStr = strings.TrimSpace(idStr)
			id, err := strconv.Atoi(idStr)
			if err != nil {
				fmt.Println("Invalid block ID. Please enter a valid number!")
				continue
			}
			block, err := LoadBlockFromDB(db, id)
			if err != nil {
				fmt.Printf("Error loading block with ID %d: %s\n", id, err)
				continue
			}
			fmt.Printf("Block with ID %d loaded successfully:\n", id)
			fmt.Printf("Data: %s\nPrevious Hash: %s\nTimestamp: %s\nHash: %s\n",
				block.Data, block.PreviousHash, block.Timestamp, block.Hash)

			// Anzeige des Bildes aus dem Block
			err = displayImageFromBlock(block)
			if err != nil {
				fmt.Printf("Error displaying image from block: %s\n", err)
				continue
			}
			LogActivity("Imgage read from Block.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}

		case 15:
			fmt.Print("Enter text to encrypt and save in a block:")
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)

			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				fmt.Printf("Error generating encryption key: %s\n", err)
				continue
			}
			encryptedData, err := EncryptData(text, key)
			if err != nil {
				fmt.Printf("Error encrypted data: %s\n", err)
				continue
			}
			encryptedHex := hex.EncodeToString(encryptedData)

			chain.AddBlock(encryptedHex)

			fmt.Printf("Data encrypted and saved in a block.\nEncryption key: %x\n", key)
			LogActivity("Encrypted Text saved to Block.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}

		case 16:
			fmt.Print("Enter filename to save blockchain log:")
			logFilename, _ := reader.ReadString('\n')
			logFilename = strings.TrimSpace(logFilename)
			err := LogBlockchain(chain, logFilename)
			if err != nil {
				fmt.Printf("Error logging blockchain to file: %s\n", err)

			} else {
				fmt.Printf("Blockchain logged to file successfilly: %s\n", logFilename)
			}
			LogActivity("Seved blockchain log:")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 17:
			fmt.Println("Enter source Peer ID:")
			sourceIDStr, _ := reader.ReadString('\n')
			sourceIDStr = strings.TrimSpace(sourceIDStr)
			sourceID, err := strconv.Atoi(sourceIDStr)
			if err != nil {
				fmt.Println("Invalid Peer ID. Please enter a valid number!")
				continue
			}
			fmt.Println("Enter destination Peer ID:")
			destIDStr, _ := reader.ReadString('\n')
			destIDStr = strings.TrimSpace(destIDStr)
			destID, err := strconv.Atoi(destIDStr)
			if err != nil {
				fmt.Println("Invalid Peer ID. Please enter a valid number!")
				continue
			}
			fmt.Println("Enter a message to send:")
			message, _ := reader.ReadString('\n')
			message = strings.TrimSpace(message)

			sourcePeer := network.GetPeerByID(sourceID)
			destPeer := network.GetPeerByID(destID)
			if sourcePeer == nil || destPeer == nil {
				fmt.Println("Invalid source or destination Peer ID. Please try agein!")
				continue
			}
			sendErr := network.SendMessageToPeer(sourcePeer.ID, destPeer.ID, message)
			if sendErr != nil {
				fmt.Printf("Error sending message from Peer %d to Peer %d: %s\n", sourceID, destID, err)
			} else {
				fmt.Printf("Message sent successfully from Peer %d to Peer %d\n", sourceID, destID)
			}
			LogActivity("Communication between Blocks.")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}
		case 18:
			fmt.Println("Exit...")
			os.Exit(0)
			LogActivity("Exit Program")
			if err != nil {
				fmt.Printf("Error logging activity: %s\n", err)
			}

		default:
			fmt.Println("Invalid option!")
		}

	}
	RunBlockchainAPI(chain, network, db)

}
