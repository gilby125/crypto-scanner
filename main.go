package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"hello/scanner"
)

var (
	entropyThreshold float64
	fileExtensions   string
	maxDepth         int
	quiet            bool
)

func main() {
	root := &cobra.Command{
		Use:   "crypto-scanner",
		Short: "Scan files and drives for lost cryptocurrency keys and seed phrases",
		Long: `Crypto Scanner is a tool for finding lost cryptocurrency keys, 
seed phrases, and high-entropy data on hard drives and external storage devices.

It can detect:
- Bitcoin WIF private keys
- Bitcoin hex private keys
- Ethereum private keys
- BIP39 mnemonic seed phrases (12, 15, 18, 21, 24 words)
- High entropy data (potential encrypted keys)`,
	}

	root.PersistentFlags().Float64VarP(&entropyThreshold, "entropy", "e", 7.5, "Entropy threshold for detecting high-entropy data (bits per byte)")
	root.PersistentFlags().StringVarP(&fileExtensions, "extensions", "x", ".txt,.log,.json,.csv,.key,.wallet,.dat,.db,.sqlite", "Comma-separated file extensions to scan")
	root.PersistentFlags().IntVarP(&maxDepth, "depth", "d", 10, "Maximum directory depth to scan")
	root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress detailed output, show only findings")

	// Scan command
	var scanCmd = &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a file or directory for crypto keys",
		Args:  cobra.MaximumNArgs(1),
		Run:   scanPath,
	}
	root.AddCommand(scanCmd)

	// Guess command for generating potential keys
	var guessCmd = &cobra.Command{
		Use:   "guess [options]",
		Short: "Generate potential keys to find lost crypto",
		Run:   guessKeys,
	}
	root.AddCommand(guessCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanPath(cmd *cobra.Command, args []string) {
	var path string
	if len(args) > 0 {
		path = args[0]
	} else {
		path = "."
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing path: %v\n", err)
		os.Exit(1)
	}

	if !quiet {
		fmt.Printf("Scanning: %s\n", absPath)
		fmt.Println(strings.Repeat("=", 60))
	}

	extensions := parseExtensions(fileExtensions)
	findings := []scanner.DetectedKey{}

	if info.IsDir() {
		filepath.Walk(absPath, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				// Check depth
				rel, _ := filepath.Rel(absPath, p)
				if strings.Count(rel, string(filepath.Separator)) >= maxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if shouldScanFile(p, extensions) {
				keys := scanFile(p)
				findings = append(findings, keys...)
			}
			return nil
		})
	} else {
		findings = scanFile(absPath)
	}

	if len(findings) > 0 {
		fmt.Println("\n🔑 FINDINGS:")
		fmt.Println(strings.Repeat("-", 60))
		for _, key := range findings {
			fmt.Printf("  [%s] %s\n", key.Type, key.Description)
			fmt.Printf("    Value: %s\n", maskValue(key.Value))
			fmt.Printf("    Location: %s:%d\n\n", key.Path, key.Line)
		}
	} else {
		if !quiet {
			fmt.Println("\nNo crypto keys or seed phrases found.")
		}
	}
}

func scanFile(path string) []scanner.DetectedKey {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var findings []scanner.DetectedKey
	scanner_ := bufio.NewScanner(file)
	lineNum := 0

	for scanner_.Scan() {
		lineNum++
		line := scanner_.Text()

		// Detect Bitcoin WIF keys
		for _, key := range scanner.DetectBitcoinWIF(line) {
			key.Path = path
			key.Line = lineNum
			findings = append(findings, key)
		}

		// Detect Ethereum keys
		for _, key := range scanner.DetectEthereumKeys(line) {
			key.Path = path
			key.Line = lineNum
			findings = append(findings, key)
		}

		// Detect Bitcoin hex keys
		for _, key := range scanner.DetectBitcoinHex(line) {
			key.Path = path
			key.Line = lineNum
			findings = append(findings, key)
		}

		// Detect mnemonic phrases
		for _, key := range scanner.DetectMnemonicPhrase(line) {
			key.Path = path
			key.Line = lineNum
			findings = append(findings, key)
		}
	}

	return findings
}

func shouldScanFile(path string, extensions map[string]bool) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return extensions[ext]
}

func parseExtensions(extensions string) map[string]bool {
	result := make(map[string]bool)
	for _, ext := range strings.Split(extensions, ",") {
		ext = strings.TrimSpace(ext)
		if ext != "" {
			result[ext] = true
		}
	}
	return result
}

func maskValue(value string) string {
	if len(value) <= 12 {
		return strings.Repeat("*", len(value))
	}
	return value[:6] + strings.Repeat("*", len(value)-10) + value[len(value)-4:]
}

func guessKeys(cmd *cobra.Command, args []string) {
	fmt.Println("🔐 Key Generator - Finding Potential Lost Crypto Keys")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("\nThis feature generates potential keys for testing purposes.")
	fmt.Println("WARNING: This is for educational/recovery use only.\n")

	// Generate some sample patterns that could match lost keys
	fmt.Println("Sample Key Patterns to Check:")
	fmt.Println(strings.Repeat("-", 40))

	// Example Ethereum key patterns
	fmt.Println("\nEthereum Private Keys (64 hex chars):")
	sampleEth := []string{
		"5KQmH8M5V2ZqL9XzY4wY8pN3tR6sT1vU7cB2nD5fG8hJ3kL6oP9qR2sT5uX8vY",
		"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	for _, k := range sampleEth {
		fmt.Printf("  %s\n", k)
	}

	// Example Bitcoin WIF
	fmt.Println("\nBitcoin WIF Keys (51-52 chars):")
	sampleWIF := []string{
		"5HueCGU8rMjxEXxiPuD5BDuZ7G8F6v8F8K9M2N3P4Q5R6S7T8U9V0W1X2Y3Z4",
		"L4rK1yDt1S6dqErkHuVh1j7Gz1G8M5qzq1QVHqVvJhJz7VqVqQq1Q1Q1Q1Q1Q1Q1Q",
	}
	for _, k := range sampleWIF {
		fmt.Printf("  %s\n", k)
	}

	fmt.Println("\n💡 Tip: Use 'scan' command to search for actual keys on drives.")
}

// scanReader scans a reader for crypto keys
func scanReader(r io.Reader) []scanner.DetectedKey {
	var findings []scanner.DetectedKey
	scanner_ := bufio.NewScanner(r)
	lineNum := 0

	for scanner_.Scan() {
		lineNum++
		line := scanner_.Text()

		for _, key := range scanner.DetectBitcoinWIF(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
		for _, key := range scanner.DetectEthereumKeys(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
		for _, key := range scanner.DetectBitcoinHex(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
		for _, key := range scanner.DetectMnemonicPhrase(line) {
			key.Line = lineNum
			findings = append(findings, key)
		}
	}

	return findings
}