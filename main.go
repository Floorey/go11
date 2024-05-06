package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Block struct {
	Data         string
	PreviousHash string
	Timestamp    time.Time
	Hash         string
	Previous     *Block // Hinzugefügtes Feld für den vorherigen Block
}
type Blockchain struct {
	Head *Block
	mu   sync.Mutex
}

func NewBlockchain() *Blockchain {
	genesisBlock := &Block{Data: "Genesis Block", PreviousHash: "", Timestamp: time.Now()}
	calculateHashAsync(genesisBlock, "") // Berechne den Hash-Wert des Genesis-Blocks im Hintergrund
	return &Blockchain{Head: genesisBlock}
}

func (chain *Blockchain) AddBlock(data string) {
	chain.mu.Lock()
	defer chain.mu.Unlock()

	newBlock := &Block{Data: data, Previous: chain.Head, Timestamp: time.Now()}
	go calculateHashAsync(newBlock, chain.Head.Hash)
	chain.Head = newBlock
}

func calculateHashAsync(block *Block, previousHash string) {
	hashBytes := sha256.Sum256([]byte(block.Data + previousHash + block.Timestamp.String()))
	block.Hash = hex.EncodeToString(hashBytes[:])
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

func main() {
	chain := NewBlockchain()

	for {
		fmt.Println("Choose an option:")
		fmt.Println("1. Insert Text")
		fmt.Println("2. Save Text in a Block")
		fmt.Println("3. Print current Block")
		fmt.Println("4. Log Hashes to File")
		fmt.Println("5. Read Text from File")
		fmt.Println("6. Read CSV from File")
		fmt.Println("7. Read JSON from File")
		fmt.Println("8. Quit Program")

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
			text, err := ReadText(filename)
			if err != nil {
				fmt.Printf("Error reading text from file: %s\n", err)
			} else {
				chain.AddBlock(text) // Text als Block an die Blockchain anhängen
				fmt.Println("Text read from file and saved in a block:", text)
			}
		case 6:
			fmt.Print("Enter filename to read CSV from: ")
			filename, _ := reader.ReadString('\n')
			filename = strings.TrimSpace(filename)
			records, err := ReadCSV(filename)
			if err != nil {
				fmt.Printf("Error reading CSV from file: %s\n", err)
			} else {
				// Jeden Datensatz als Textblock an die Blockchain anhängen
				for _, record := range records {
					text := strings.Join(record, ", ")
					chain.AddBlock(text)
				}
				fmt.Println("CSV read from file and saved in blocks:", records)
			}
		case 7:
			fmt.Print("Enter filename to read JSON from: ")
			filename, _ := reader.ReadString('\n')
			filename = strings.TrimSpace(filename)
			var jsonData interface{}
			err := ReadJSON(filename, &jsonData)
			if err != nil {
				fmt.Printf("Error reading JSON from file: %s\n", err)
			} else {
				jsonText, _ := json.Marshal(jsonData)
				chain.AddBlock(string(jsonText)) // JSON als Block an die Blockchain anhängen
				fmt.Println("JSON read from file and saved in a block:", jsonData)
			}
		case 8:
			fmt.Println("Quitting program...")
			os.Exit(0)
		default:
			fmt.Println("Invalid option!")
		}
	}
}
