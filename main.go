package main

//go:generate goimports -w .

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
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
	Previous     *Block // Hinzugefügtes Feld für den vorherigen Block
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
	previousBlock := chain.Blocks[len(chain.Blocks)-1]
	newBlock := &Block{
		Data:         data,
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

	network.PrintPeers()

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
		fmt.Println("14. Exit!")

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
		case 2:
			fmt.Print("Enter text to save in a block: ")
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			chain.AddBlock(text)
			fmt.Println("Text saved in a block.")
		case 3:
			fmt.Println("Current Block:")
			chain.PrintBlockchain()
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
		case 11:
			if chain.DB != nil {
				fmt.Println("Blockchain saving to database is currently enabled. Disabling...")
				chain.DB = nil
			} else {
				fmt.Println("Blockchain saving to database is currently disabled. Enabling...")
				chain.DB = db
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
		case 13:
			fmt.Println("Enter the ID of the block to load:")
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

		case 14:
			fmt.Println("Exit!")
			os.Exit(0)

		default:
			fmt.Println("Invalid option!")
		}
	}
}
