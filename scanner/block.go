package scanner

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
)

// BlockScanner reads raw block devices and finds crypto keys
type BlockScanner struct {
	blockSize    int
	entropyThresh float64
}

// NewBlockScanner creates a new block scanner
func NewBlockScanner(blockSize int, entropyThreshold float64) *BlockScanner {
	if blockSize == 0 {
		blockSize = 512 // Default sector size
	}
	if entropyThreshold == 0 {
		entropyThreshold = 7.5
	}
	return &BlockScanner{
		blockSize:    blockSize,
		entropyThresh: entropyThreshold,
	}
}

// ScanBlockDevice scans a raw block device for crypto keys
func (bs *BlockScanner) ScanBlockDevice(path string) ([]DetectedKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening block device: %w", err)
	}
	defer file.Close()

	var findings []DetectedKey
	buf := make([]byte, bs.blockSize)

	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return findings, nil // Return partial findings
		}

		// Scan this block for keys
		keys := bs.scanBlock(buf[:n], path)
		findings = append(findings, keys...)
	}

	return findings, nil
}

// ScanRawFile scans any file in binary mode
func (bs *BlockScanner) ScanRawFile(path string) ([]DetectedKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []DetectedKey
	buf := make([]byte, bs.blockSize)

	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return findings, nil
		}

		keys := bs.scanBlock(buf[:n], path)
		findings = append(findings, keys...)
	}

	return findings, nil
}

// scanBlock scans a single block for crypto patterns
func (bs *BlockScanner) scanBlock(data []byte, path string) []DetectedKey {
	var findings []DetectedKey

	// Convert to string for text-based pattern matching
	text := string(data)

	// Detect Bitcoin WIF keys
	for _, key := range detectBitcoinWIFBinary(data) {
		key.Path = path
		findings = append(findings, key)
	}

	// Detect Ethereum keys
	for _, key := range detectEthereumKeysBinary(data) {
		key.Path = path
		findings = append(findings, key)
	}

	// Detect hex keys
	for _, key := range detectHexKeysBinary(data) {
		key.Path = path
		findings = append(findings, key)
	}

	// Check entropy for high-entropy regions
	if IsHighEntropy(data, bs.entropyThresh) {
		// Found high entropy data - could contain keys
		findings = append(findings, DetectedKey{
			Type:        KeyTypeUnknown,
			Value:       fmt.Sprintf("High entropy region (%d bytes)", len(data)),
			Path:        path,
			Description: fmt.Sprintf("High entropy data (%.2f bits/byte)", EstimateBitsOfEntropy(data)),
			Entropy:     EstimateBitsOfEntropy(data),
		})
	}

	// Also scan as text for mnemonic phrases
	for _, key := range DetectMnemonicPhrase(text) {
		key.Path = path
		findings = append(findings, key)
	}

	return findings
}

// detectBitcoinWIFBinary finds Bitcoin WIF keys in binary data
func detectBitcoinWIFBinary(data []byte) []DetectedKey {
	var findings []DetectedKey
	
	// WIF regex works on bytes
	re := regexp.MustCompile(`[5KL][a-km-zA-HJ-NP-Z1-9]{50,51}`)
	
	// Convert to string for regex (be careful with null bytes)
	text := string(data)
	matches := re.FindAllStringIndex(text, -1)
	
	for _, match := range matches {
		key := text[match[0]:match[1]]
		if isValidBitcoinWIF(key) {
			findings = append(findings, DetectedKey{
				Type:        KeyTypeBitcoinWIF,
				Value:       key,
				Description: "Bitcoin WIF Private Key",
			})
		}
	}
	
	return findings
}

// detectEthereumKeysBinary finds Ethereum keys in binary data
func detectEthereumKeysBinary(data []byte) []DetectedKey {
	var findings []DetectedKey
	
	// Look for 64 consecutive hex characters
	re := regexp.MustCompile(`(?:0x)?[a-fA-F0-9]{64}`)
	
	text := string(data)
	matches := re.FindAllStringIndex(text, -1)
	
	for _, match := range matches {
		key := text[match[0]:match[1]]
		// Remove 0x prefix if present
		if len(key) > 2 && key[:2] == "0x" {
			key = key[2:]
		}
		findings = append(findings, DetectedKey{
			Type:        KeyTypeEthereumPrivate,
			Value:       key,
			Description: "Ethereum Private Key",
		})
	}
	
	return findings
}

// detectHexKeysBinary finds hex keys in binary data
func detectHexKeysBinary(data []byte) []DetectedKey {
	var findings []DetectedKey
	
	// Look for 64-char hex strings (32 bytes)
	re := regexp.MustCompile(`[a-fA-F0-9]{64}`)
	
	text := string(data)
	matches := re.FindAllStringIndex(text, -1)
	
	for _, match := range matches {
		key := text[match[0]:match[1]]
		if len(key) == 64 {
			findings = append(findings, DetectedKey{
				Type:        KeyTypeBitcoinHex,
				Value:       key,
				Description: "Bitcoin Hex Private Key",
			})
		}
	}
	
	return findings
}

// ScanCarvedFile carves files from raw disk data by looking for file signatures
func (bs *BlockScanner) ScanCarvedFile(data []byte, offset int64) []DetectedKey {
	var findings []DetectedKey
	
	// Check entropy
	if IsHighEntropy(data, bs.entropyThresh) {
		findings = append(findings, DetectedKey{
			Type:        KeyTypeUnknown,
			Value:       fmt.Sprintf("Carved file at offset %d", offset),
			Path:        fmt.Sprintf("offset:%d", offset),
			Description: fmt.Sprintf("Potential file with keys (%d bytes, entropy: %.2f)", len(data), EstimateBitsOfEntropy(data)),
			Entropy:     EstimateBitsOfEntropy(data),
		})
	}
	
	return findings
}

// ScanStream scans a stream (like stdin) for keys
func ScanStream(r io.Reader) []DetectedKey {
	var findings []DetectedKey
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, key := range DetectBitcoinWIF(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
		for _, key := range DetectEthereumKeys(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
		for _, key := range DetectBitcoinHex(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
		for _, key := range DetectMnemonicPhrase(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
	}

	return findings
}

// FindPrintableStrings extracts printable strings from binary data
// This is useful for finding base58 keys in binary blobs
func FindPrintableStrings(data []byte, minLength int) []string {
	var strings []string
	var current bytes.Buffer

	for _, b := range data {
		// Printable ASCII range plus common whitespace
		if (b >= 32 && b <= 126) || b == '\t' || b == '\n' || b == '\r' {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLength {
				strings = append(strings, current.String())
			}
			current.Reset()
		}
	}

	if current.Len() >= minLength {
		strings = append(strings, current.String())
	}

	return strings
}

// ParseSector parses a disk sector and returns readable content
func ParseSector(data []byte) map[string]interface{} {
	result := make(map[string]interface{})
	
	// Check for MBR signature
	if len(data) >= 512 {
		signature := binary.LittleEndian.Uint16(data[510:512])
		if signature == 0xAA55 {
			result["mbr"] = true
		}
	}
	
	// Extract strings
	strings := FindPrintableStrings(data, 12)
	if len(strings) > 0 {
		result["strings"] = strings[:min(10, len(strings))]
	}
	
	// Check entropy
	result["entropy"] = EstimateBitsOfEntropy(data)
	
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}