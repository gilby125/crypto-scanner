# Crypto Scanner

A tool for finding lost cryptocurrency keys, seed phrases, and high-entropy data on hard drives and external storage devices.

## Features

- **Bitcoin WIF private key detection** (51-52 characters, starts with '5', 'K', or 'L')
- **Bitcoin hex private key detection** (64 hex characters)
- **Ethereum private key detection** (64 hex characters, with or without 0x prefix)
- **BIP39 mnemonic phrase detection** (12, 15, 18, 21, or 24 word phrases)
- **High entropy data detection** (potential encrypted keys)

## Installation

```bash
# Clone the repository
git clone https://github.com/gilby125/crypto-scanner.git
cd crypto-scanner

# Build the binary
go build -o crypto-scanner .

# Or run directly
go run . [command] [options]
```

## Usage

### Scan a Directory

```bash
# Scan current directory
./crypto-scanner scan

# Scan a specific path (external drive, folder, etc.)
./crypto-scanner scan /path/to/scan

# Scan with custom settings
./crypto-scanner scan --entropy 8.0 --depth 20 /mnt/external-drive
```

### Scan a Single File

```bash
./crypto-scanner scan /path/to/file.txt
```

### Command Line Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--entropy` | `-e` | 7.5 | Entropy threshold for detecting high-entropy data (bits per byte) |
| `--extensions` | `-x` | .txt,.log,.json,.csv,.key,.wallet,.dat,.db,.sqlite | Comma-separated file extensions to scan |
| `--depth` | `-d` | 10 | Maximum directory depth to scan |
| `--quiet` | `-q` | false | Suppress detailed output, show only findings |

### Examples

```bash
# Scan external drive with high entropy detection
./crypto-scanner scan --entropy 8.0 /Volumes/ExternalDrive

# Scan only .txt and .key files
./crypto-scanner scan --extensions ".txt,.key" /path/to/scan

# Quiet mode - only show findings
./crypto-scanner scan --quiet /path/to/scan

# Scan with unlimited depth (be careful!)
./crypto-scanner scan --depth 0 /path/to/scan
```

## Key Detection

### Bitcoin WIF Keys
- Format: 51-52 characters starting with '5', 'K', or 'L'
- Example: `5HueCGU8rMjxEXxiPuD5BDuZ7G8F6v8F8K9M2N3P4Q5R6S7T8U9V0W1X2Y3Z4`

### Ethereum Keys
- Format: 64 hexadecimal characters (with or without 0x prefix)
- Example: `0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`

### Bitcoin Hex Keys
- Format: 64 hexadecimal characters (without 0x prefix)
- Example: `1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`

### BIP39 Mnemonic Phrases
- 12, 15, 18, 21, or 24 words from the BIP39 wordlist
- Example: `abandon ability able about above absent absorb abstract absurd abuse access accident`

## Security Notes

⚠️ **WARNING**: This tool is for educational and recovery purposes only.

- Found keys should be verified before use
- Never share private keys with anyone
- Consider the legal implications of using found keys

## Development

```bash
# Run tests
go test ./...

# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o crypto-scanner-linux .
GOOS=darwin GOARCH=amd64 go build -o crypto-scanner-macos .
GOOS=windows GOARCH=amd64 go build -o crypto-scanner-windows.exe .
```

## License

MIT License - See LICENSE file for details.