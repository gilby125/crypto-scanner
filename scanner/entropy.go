package scanner

import (
	"math"
)

// CalculateShannonEntropy calculates the Shannon entropy of a byte slice
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count frequency of each byte
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// IsHighEntropy checks if data has high entropy (potential encrypted/compressed data)
// Typical threshold is 7.5 bits per byte for high entropy
func IsHighEntropy(data []byte, threshold float64) bool {
	entropy := CalculateShannonEntropy(data)
	return entropy >= threshold
}

// EstimateBitsOfEntropy returns the estimated bits of entropy per byte
func EstimateBitsOfEntropy(data []byte) float64 {
	return CalculateShannonEntropy(data)
}