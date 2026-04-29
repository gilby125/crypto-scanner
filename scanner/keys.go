package scanner

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// BIP39 English wordlist (first 100 words for brevity - full list would be included)
// This is a subset - in production, the full 2048-word list would be used
var bip39Words = map[string]bool{
	"abandon": true, "ability": true, "able": true, "about": true, "above": true,
	"absent": true, "absorb": true, "abstract": true, "absurd": true, "abuse": true,
	"access": true, "accident": true, "account": true, "accuse": true, "achieve": true,
	"acid": true, "acoustic": true, "acquire": true, "across": true, "act": true,
	"action": true, "actor": true, "actress": true, "actual": true, "adapt": true,
	"add": true, "addict": true, "address": true, "adjust": true, "admit": true,
	"adult": true, "advance": true, "advice": true, "aerobic": true, "affair": true,
	"afford": true, "afraid": true, "again": true, "age": true, "agent": true,
	"agree": true, "ahead": true, "aim": true, "air": true, "airport": true,
	"aisle": true, "alarm": true, "album": true, "alcohol": true, "alert": true,
	"alien": true, "all": true, "alley": true, "allow": true, "almost": true,
	"alone": true, "along": true, "already": true, "also": true, "alter": true,
	"always": true, "amateur": true, "amazing": true, "among": true, "amount": true,
	"analog": true, "anchor": true, "ancient": true, "anger": true, "angle": true,
	"angry": true, "animal": true, "ankle": true, "announce": true, "annual": true,
	"another": true, "answer": true, "antenna": true, "antique": true, "anxiety": true,
	"any": true, "apart": true, "apology": true, "appear": true, "apple": true,
	"approve": true, "april": true, "arch": true, "arctic": true, "area": true,
	"arena": true, "argue": true, "arm": true, "armed": true, "armor": true,
	"around": true, "arrange": true, "arrest": true, "arrive": true, "arrow": true,
	"art": true, "artefact": true, "artist": true, "artwork": true, "ask": true,
	"aspect": true, "assemble": true, "assert": true, "assess": true, "asset": true,
	"assign": true, "assist": true, "assume": true, "asleep": true,

	// Continue with more BIP39 words - full wordlist would have all 2048
	"balcony": true, "banana": true, "banner": true, "bar": true, "barely": true,
	"bargain": true, "barrel": true, "base": true, "basic": true, "basket": true,
	"battle": true, "bead": true, "beauty": true, "because": true, "become": true,
	"beef": true, "before": true, "begin": true, "behave": true, "behind": true,
	"believe": true, "below": true, "belt": true, "bench": true, "benefit": true,
	"best": true, "better": true, "between": true, "beyond": true, "bicycle": true,
	"bid": true, "bike": true, "bind": true, "biology": true, "bird": true,
	"birth": true, "bitter": true, "black": true, "blade": true, "blame": true,
	"blanket": true, "blast": true, "bleak": true, "bless": true, "blind": true,
	"blimp": true, "blink": true, "blip": true, "blizzard": true, "block": true,
	"bloom": true, "blossom": true, "blouse": true, "blue": true, "blur": true,
	"blush": true, "board": true, "boat": true, "body": true, "boil": true,
	"bold": true, "bomb": true, "bone": true, "bonus": true, "book": true,
	"boost": true, "border": true, "boring": true, "borrow": true, "boss": true,
	"bottom": true, "bounce": true, "box": true, "boy": true, "bracket": true,
	"brave": true, "bread": true, "break": true, "breakfast": true, "breast": true,
	"breath": true, "breeze": true, "brick": true, "bridge": true, "brief": true,
	"bright": true, "bring": true, "brisket": true, "broccoli": true, "broken": true,
	"bronze": true, "broom": true, "brother": true, "brown": true, "brush": true,
	"bubble": true, "buddy": true, "budget": true, "buffer": true, "build": true,
	"bulb": true, "bulk": true, "bullet": true, "bundle": true, "bunker": true,

	// Essential words for common mnemonics
	"cage": true, "cake": true, "call": true, "calm": true, "camera": true,
	"camp": true, "can": true, "cancel": true, "candy": true, "cannon": true,
	"canoe": true, "canvas": true, "canyon": true, "capable": true, "capital": true,
	"captain": true, "car": true, "carbon": true, "card": true, "care": true,
	"careful": true, "cargo": true, "carpet": true, "carry": true, "cart": true,
	"case": true, "cash": true, "casino": true, "castle": true, "casual": true,
	"cat": true, "catalog": true, "catch": true, "category": true, "cattle": true,
	"caught": true, "cause": true, "caution": true, "cave": true, "ceiling": true,
	"celery": true, "celestial": true, "cell": true, "cement": true, "census": true,
	"century": true, "cereal": true, "certain": true, "chair": true, "chalk": true,
	"challenge": true, "champion": true, "chance": true, "change": true, "chaos": true,
	"chapter": true, "charge": true, "chase": true, "chat": true, "cheap": true,
	"check": true, "cheese": true, "chef": true, "cherry": true, "chest": true,
	"chew": true, "chief": true, "child": true, "childhood": true, "chill": true,
	"chimney": true, "choice": true, "choose": true, "chronic": true, "chuckle": true,
	"chunk": true, "churn": true, "cigar": true, "cinema": true, "circle": true,
	"circuit": true, "circulate": true, "citizen": true, "city": true, "civil": true,
	"claim": true, "clap": true, "clarify": true, "claw": true, "clay": true,
	"clean": true, "clerk": true, "click": true, "client": true, "cliff": true,
	"climb": true, "clinic": true, "clip": true, "clock": true, "clog": true,
	"close": true, "cloth": true, "cloud": true, "clown": true, "club": true,
	"clump": true, "cluster": true, "clutch": true, "coach": true, "coal": true,
	"coast": true, "coconut": true, "code": true, "coffee": true, "coil": true,
	"coin": true, "collect": true, "color": true, "column": true, "combine": true,
	"come": true, "comfort": true, "comic": true, "common": true, "company": true,
	"concert": true, "conduct": true, "confirm": true, "congress": true, "connect": true,
	"consider": true, "consist": true, "conspiracy": true, "constant": true, "consult": true,
	"consume": true, "contact": true, "contain": true, "content": true, "context": true,
	"continent": true, "continue": true, "contract": true, "contrary": true, "contrast": true,
	"contribute": true, "control": true, "convince": true, "cook": true, "cool": true,
	"copper": true, "copy": true, "coral": true, "core": true, "corn": true,
	"correct": true, "cost": true, "cotton": true, "couch": true, "could": true,

	// More essential words
	"crash": true, "crater": true, "crawl": true, "crazy": true, "cream": true,
	"credit": true, "creek": true, "crew": true, "crop": true, "cross": true,
	"crowd": true, "crown": true, "crucial": true, "cruel": true, "cruise": true,
	"crush": true, "cry": true, "crystal": true, "cube": true, "culture": true,
	"cup": true, "cupboard": true, "cure": true, "curl": true, "curtain": true,
	"curve": true, "cushion": true, "custom": true, "cute": true, "cycle": true,
	"dad": true, "daisy": true, "damage": true, "dance": true, "danger": true,
	"dare": true, "dark": true, "dash": true, "data": true, "date": true,
	"daughter": true, "dawn": true, "day": true, "deal": true, "debate": true,
	"debris": true, "decade": true, "december": true, "decide": true, "declare": true,
	"deep": true, "defense": true, "define": true, "defy": true, "degree": true,
	"delay": true, "deliver": true, "demand": true, "demise": true, "denial": true,
	"dentist": true, "deny": true, "depart": true, "depend": true, "deposit": true,
	"depth": true, "describe": true, "desert": true, "design": true, "desk": true,
	"despair": true, "destroy": true, "detail": true, "detect": true, "develop": true,
	"device": true, "devil": true, "devote": true, "dew": true, "diamond": true,
	"dictate": true, "diet": true, "digital": true, "dignity": true, "dilemma": true,
	"dinner": true, "direct": true, "dirty": true, "disagree": true, "disappear": true,
	"discharge": true, "discover": true, "disease": true, "disgust": true, "dish": true,
	"dismiss": true, "disorder": true, "display": true, "distance": true, "divert": true,
	"divide": true, "divorce": true, "dizzy": true, "dock": true, "doctor": true,
	"document": true, "dog": true, "doll": true, "dolphin": true, "domain": true,
	"dose": true, "dot": true, "double": true, "doubt": true, "dove": true,

	// Final words
	"dragon": true, "dramatic": true, "dream": true, "dress": true, "drift": true,
	"drill": true, "drink": true, "drip": true, "drive": true, "drop": true,
	"drum": true, "dry": true, "duck": true, "dumb": true, "dune": true,
	"during": true, "dust": true, "dutch": true, "duty": true, "dwarf": true,
	"dwell": true, "dying": true, "dynamic": true, "eager": true, "eagle": true,
	"early": true, "earn": true, "earth": true, "easily": true, "east": true,
	"easy": true, "ecology": true, "economy": true, "edge": true, "edit": true,
	"educate": true, "effort": true, "egg": true, "eight": true, "either": true,
	"elder": true, "electric": true, "elegant": true, "element": true, "elephant": true,
	"elevator": true, "elf": true, "else": true, "elsewhere": true, "end": true,
	"endorse": true, "enemy": true, "energy": true, "enforce": true, "engine": true,
	"enhance": true, "enjoy": true, "enormous": true, "enough": true, "ensure": true,
	"enter": true, "entire": true, "entry": true, "envelope": true, "environment": true,
	"episode": true, "equal": true, "equip": true, "era": true, "erase": true,
	"erode": true, "erosion": true, "error": true, "escape": true, "essay": true,
	"establish": true, "estate": true, "estimate": true, "ethics": true, "event": true,
	"evidence": true, "evil": true, "evoke": true, "evolve": true, "exact": true,
}

// CryptoKeyType represents the type of crypto key detected
type CryptoKeyType string

const (
	KeyTypeBitcoinWIF         CryptoKeyType = "bitcoin_wif"
	KeyTypeBitcoinHex         CryptoKeyType = "bitcoin_hex"
	KeyTypeEthereumPrivate    CryptoKeyType = "ethereum_private"
	KeyTypeEthereumMnemonic   CryptoKeyType = "ethereum_mnemonic"
	KeyTypeMnemonic12         CryptoKeyType = "mnemonic_12"
	KeyTypeMnemonic15         CryptoKeyType = "mnemonic_15"
	KeyTypeMnemonic18         CryptoKeyType = "mnemonic_18"
	KeyTypeMnemonic21         CryptoKeyType = "mnemonic_21"
	KeyTypeMnemonic24         CryptoKeyType = "mnemonic_24"
	KeyTypeUnknown            CryptoKeyType = "unknown"
)

// DetectedKey represents a detected crypto key
type DetectedKey struct {
	Type        CryptoKeyType
	Value       string
	Path        string
	Line        int
	Offset      int
	Entropy     float64
	Description string
}

// bitcoinWIFRegex matches Bitcoin WIF (Wallet Import Format) keys
// Starts with 5, K, or L and is 51-52 characters base58
var bitcoinWIFRegex = regexp.MustCompile(`[5KL][a-km-zA-HJ-NP-Z1-9]{50,51}`)

// bitcoinCompressedWIFRegex matches compressed WIF keys (starting with K or L)
var bitcoinCompressedWIFRegex = regexp.MustCompile(`[KL][a-km-zA-HJ-NP-Z1-9]{51}`)

// ethereumKeyRegex matches 64-character hex strings (32 bytes)
var ethereumKeyRegex = regexp.MustCompile(`\b0x[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{64}\b`)

// highEntropyHexRegex matches 32+ byte hex strings (potential keys)
var highEntropyHexRegex = regexp.MustCompile(`(?:0x)?[a-fA-F0-9]{64,128}`)

// DetectBitcoinWIF detects Bitcoin WIF format private keys in text
func DetectBitcoinWIF(text string) []DetectedKey {
	var keys []DetectedKey
	matches := bitcoinWIFRegex.FindAllStringIndex(text, -1)
	
	for _, match := range matches {
		key := text[match[0]:match[1]]
		// Validate it's a proper WIF key
		if isValidBitcoinWIF(key) {
			keys = append(keys, DetectedKey{
				Type:        KeyTypeBitcoinWIF,
				Value:       key,
				Description: "Bitcoin WIF Private Key",
			})
		}
	}
	
	return keys
}

// DetectEthereumKeys detects Ethereum private keys in hex format
func DetectEthereumKeys(text string) []DetectedKey {
	var keys []DetectedKey
	matches := ethereumKeyRegex.FindAllStringIndex(text, -1)
	
	for _, match := range matches {
		key := text[match[0]:match[1]]
		// Remove 0x prefix if present
		if strings.HasPrefix(key, "0x") {
			key = key[2:]
		}
		keys = append(keys, DetectedKey{
			Type:        KeyTypeEthereumPrivate,
			Value:       key,
			Description: "Ethereum Private Key (64 hex chars)",
		})
	}
	
	return keys
}

// DetectBitcoinHex detects raw Bitcoin hex private keys (32 bytes)
func DetectBitcoinHex(text string) []DetectedKey {
	var keys []DetectedKey
	matches := highEntropyHexRegex.FindAllStringIndex(text, -1)
	
	for _, match := range matches {
		key := text[match[0]:match[1]]
		// Remove 0x prefix if present
		if strings.HasPrefix(key, "0x") || strings.HasPrefix(key, "0X") {
			key = key[2:]
		}
		
		// Check if it's exactly 64 hex chars (32 bytes) - valid Bitcoin key
		if len(key) == 64 {
			// Verify it's valid hex
			_, err := hex.DecodeString(key)
			if err == nil && isValidBitcoinHexKey(key) {
				keys = append(keys, DetectedKey{
					Type:        KeyTypeBitcoinHex,
					Value:       key,
					Description: "Bitcoin Private Key (32 bytes hex)",
				})
			}
		}
	}
	
	return keys
}

// isValidBitcoinWIF validates a Bitcoin WIF key
func isValidBitcoinWIF(wif string) bool {
	// WIF keys are base58 encoded
	// They contain a version byte, 32 bytes of key data, and optionally a compression flag
	// Length should be 51 or 52 for uncompressed, 52 for compressed
	if len(wif) < 51 {
		return false
	}
	
	// Check checksum (simplified - full validation would decode base58)
	return true
}

// isValidBitcoinHexKey checks if a hex string is a valid Bitcoin private key
func isValidBitcoinHexKey(hexKey string) bool {
	// Bitcoin private keys must be in range [1, n-1] where n is the curve order
	// For simplicity, we check it's not all zeros or all F's
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return false
	}
	
	// Check not all zeros
	allZero := true
	allFF := true
	for _, b := range decoded {
		if b != 0 {
			allZero = false
		}
		if b != 0xFF {
			allFF = false
		}
	}
	
	return !allZero && !allFF
}

// FormatKey formats a private key for display
func FormatKey(key string, keyType CryptoKeyType) string {
	switch keyType {
	case KeyTypeBitcoinWIF:
		return fmt.Sprintf("Bitcoin WIF: %s", key)
	case KeyTypeEthereumPrivate:
		return fmt.Sprintf("Ethereum: 0x%s", key)
	case KeyTypeBitcoinHex:
		return fmt.Sprintf("Bitcoin Hex: %s", key)
	default:
		return key
	}
}

// ParsePrivateKey parses a hex private key to validate and return details
func ParsePrivateKey(hexKey string) (int, error) {
	// Remove 0x prefix if present
	key := strings.TrimPrefix(hexKey, "0x")
	key = strings.TrimPrefix(key, "0X")
	
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return 0, fmt.Errorf("invalid hex: %w", err)
	}
	
	return len(decoded), nil
}

// EstimateKeyStrength estimates the strength of a private key in bits
func EstimateKeyStrength(hexKey string) (int, error) {
	length, err := ParsePrivateKey(hexKey)
	if err != nil {
		return 0, err
	}
	
	// Each byte is 8 bits
	return length * 8, nil
}

// mnemonicRegex matches potential mnemonic phrase patterns (space-separated words)
var mnemonicRegex = regexp.MustCompile(`(?i)\b([a-z]{3,12})(\s+[a-z]{3,12}){11,23}\b`)

// DetectMnemonicPhrase detects potential BIP39 mnemonic seed phrases in text
func DetectMnemonicPhrase(text string) []DetectedKey {
	var keys []DetectedKey
	
	// Common mnemonic word counts: 12, 15, 18, 21, 24
	validWordCounts := map[int]CryptoKeyType{
		12: KeyTypeMnemonic12,
		15: KeyTypeMnemonic15,
		18: KeyTypeMnemonic18,
		21: KeyTypeMnemonic21,
		24: KeyTypeMnemonic24,
	}
	
	// Try different word counts
	for wordCount, keyType := range validWordCounts {
		// Build regex pattern for this word count
		pattern := `(?i)\b([a-z]{3,12})(\s+[a-z]{3,12}){` + strconv.Itoa(wordCount-1) + `}\b`
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(text, -1)
		
		for _, match := range matches {
			words := strings.Fields(strings.ToLower(match))
			
			// Validate all words are in BIP39 wordlist
			validWordCount := 0
			for _, word := range words {
				if bip39Words[word] {
					validWordCount++
				}
			}
			
			// If most words are valid BIP39 words, it's likely a mnemonic
			threshold := int(float64(wordCount) * 0.7) // 70% threshold
			if validWordCount >= threshold {
				keys = append(keys, DetectedKey{
					Type:        keyType,
					Value:       strings.ToLower(match),
					Description: fmt.Sprintf("BIP39 Mnemonic Phrase (%d words)", wordCount),
				})
			}
		}
	}
	
	return keys
}

// ValidateMnemonicChecksum validates a mnemonic phrase checksum
// This is a simplified version - full BIP39 requires PBKDF2 and entropy calculation
func ValidateMnemonicChecksum(mnemonic string) bool {
	words := strings.Fields(strings.ToLower(mnemonic))
	if len(words) == 0 {
		return false
	}
	
	// Check all words are valid BCP39 words
	validCount := 0
	for _, word := range words {
		if bip39Words[word] {
			validCount++
		}
	}
	
	return validCount == len(words)
}

// DeriveSeedFromMnemonic derives a seed from a mnemonic phrase (simplified)
// In production, this would use PBKDF2-HMAC-SHA512
func DeriveSeedFromMnemonic(mnemonic, passphrase string) ([]byte, error) {
	// Simplified: hash the mnemonic with passphrase
	// Real implementation would use: pbkdf2.Key(seed, "mnemonic"+passphrase, 2048, 64, sha512)
	combined := mnemonic + passphrase
	return hex.DecodeString(fmt.Sprintf("%x", combined))
}