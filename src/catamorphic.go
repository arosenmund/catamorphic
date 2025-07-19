// patcher.go
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// computeHash opens the file at `path`, hashes it with either MD5 or SHA-256,
// and returns the hex digest string.
func computeHash(path, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var h io.Writer
	switch algo {
	case "md5":
		h = md5.New()
	case "sha256":
		h = sha256.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algo)
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := h.(interface{ Sum([]byte) []byte }).Sum(nil)
	return hex.EncodeToString(sum), nil
}

// secureRandomString generates a cryptographically‐secure random string of length n
// using [a–zA–Z0–9]. Returns an error if n ≤ 0.
func secureRandomString(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("length must be positive")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b), nil
}

// backupFile simply copies src → src+".bak" (0644) and returns the backup path.
func backupFile(src string) (string, error) {
	bak := src + ".bak"
	if err := ioutil.WriteFile(bak, mustReadAll(src), 0644); err != nil {
		return "", err
	}
	return bak, nil
}

// mustReadAll reads the entire file into memory, or log.Fatal if it cannot.
func mustReadAll(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("unable to read %s: %v", path, err)
	}
	return data
}

// replaceAllInPlace finds every occurrence of origBytes inside data,
// then copies replBytes over that region (they must be exactly the same length).
func replaceAllInPlace(data []byte, origBytes, replBytes []byte) int {
	if len(origBytes) != len(replBytes) {
		log.Fatalf("internal error: orig and repl must have identical length; got %d vs %d", len(origBytes), len(replBytes))
	}
	count := 0
	searchOffset := 0
	for {
		idx := bytes.Index(data[searchOffset:], origBytes)
		if idx < 0 {
			break
		}
		idx += searchOffset
		copy(data[idx:idx+len(origBytes)], replBytes)
		count++
		searchOffset = idx + len(origBytes)
		if searchOffset >= len(data) {
			break
		}
	}
	return count
}

func main() {
	// ─── CLI FLAGS ───────────────────────────────────────────────────────────
	inFile := flag.String("in", "", "input Go‐built binary (required)")
	outFile := flag.String("out", "", "output file path (required)")
	algo := flag.String("hash", "md5", "hash algorithm: md5 or sha256")
	keyLen := flag.Int("keylen", 16, "length of random key to inject")
	offset := flag.Int("offset", -1, "byte offset to patch at; -1 = append")
	replaceVer := flag.String("replace-ver", "",
		"overwrite every instance of Go version string in‐place (auto‐pad/truncate)")
	sigFile := flag.String("sig-file", "",
		"path to JSON signature file (original→replacement strings) (optional)")
	doBackup := flag.Bool("backup", false, "create a .bak of the original before patching")
	flag.Parse()

	if *inFile == "" || *outFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// ─── BACKUP ORIGINAL (optional) ────────────────────────────────────────────
	if *doBackup {
		bak, err := backupFile(*inFile)
		if err != nil {
			log.Fatalf("🔒 backup failed: %v", err)
		}
		fmt.Printf("🔒 Backed up original to %s\n", bak)
	}

	// ─── ORIGINAL HASH ────────────────────────────────────────────────────────
	origHash, err := computeHash(*inFile, *algo)
	if err != nil {
		log.Fatalf("cannot hash original: %v", err)
	}
	fmt.Printf("📝 Original %s hash: %s → %s\n",
		filepath.Base(*inFile), *algo, origHash)

	// ─── LOAD ENTIRE BINARY INTO MEMORY ───────────────────────────────────────
	data, err := ioutil.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("read error: %v", err)
	}

	// ─── LOAD & APPLY SIGNATURES (if provided) ────────────────────────────────
	if *sigFile != "" {
		sigBytes, err := ioutil.ReadFile(*sigFile)
		if err != nil {
			log.Fatalf("cannot read signature file: %v", err)
		}

		var sigMap map[string]string
		if err := json.Unmarshal(sigBytes, &sigMap); err != nil {
			log.Fatalf("invalid JSON in signature file: %v", err)
		}

		for orig, repl := range sigMap {
			origBytes := []byte(orig)
			if len(origBytes) == 0 {
				continue // skip empty keys
			}

			// Prepare replacement: pad or truncate to match len(origBytes)
			rep := repl
			if len(rep) < len(origBytes) {
				rep = rep + strings.Repeat("\x00", len(origBytes)-len(rep))
			} else if len(rep) > len(origBytes) {
				rep = rep[:len(origBytes)]
			}
			replBytes := []byte(rep)

			// Replace all occurrences in-place
			found := replaceAllInPlace(data, origBytes, replBytes)
			if found > 0 {
				fmt.Printf("🔄 Replaced %d instance(s) of signature %q with %q\n",
					found, orig, rep)
			} else {
				fmt.Printf("⚠️  Signature %q not found; no replacements made\n", orig)
			}
		}
	}

	// ─── DETECT GO VERSION & COLLECT ORIGINAL STRING ──────────────────────────
	var verString string
	var verLen int
	if info, err := buildinfo.ReadFile(*inFile); err != nil {
		fmt.Printf("⚠️  No Go buildinfo: %v\n", err)
		if *replaceVer != "" {
			log.Fatalf("no Go version to replace in this binary")
		}
	} else {
		verString = info.GoVersion
		verLen = len(verString)
		fmt.Printf("🔍 Detected Go version: %s\n", verString)
	}

	// ─── OVERWRITE EVERY INSTANCE OF GO VERSION (auto‐pad/truncate) ─────────────
	if *replaceVer != "" {
		if verString == "" {
			log.Fatalf("no Go version found to replace")
		}

		origVerBytes := []byte(verString)
		repBase := *replaceVer

		// Pad or truncate the base replacement string to orig length
		if len(repBase) < verLen {
			repBase = repBase + strings.Repeat("\x00", verLen-len(repBase))
		} else if len(repBase) > verLen {
			repBase = repBase[:verLen]
		}
		repBytes := []byte(repBase)

		// Replace all occurrences of the Go version string
		found := replaceAllInPlace(data, origVerBytes, repBytes)
		if found > 0 {
			fmt.Printf("🔄 Overwrote %d instance(s) of Go version %q with %q\n",
				found, verString, repBase)
		} else {
			fmt.Printf("⚠️  Original Go version %q not found; no replacements made\n", verString)
		}
	}

	// ─── GENERATE & INJECT RANDOM KEY ─────────────────────────────────────────
	key, err := secureRandomString(*keyLen)
	if err != nil {
		log.Fatalf("key gen error: %v", err)
	}
	fmt.Printf("🧩 Injecting random key (%d bytes): %s\n", *keyLen, key)

	patch := []byte(key)
	if *offset >= 0 {
		if *offset > len(data) {
			log.Fatalf("offset %d beyond end of file (%d bytes)", *offset, len(data))
		}
		copy(data[*offset:], patch)
	} else {
		data = append(data, patch...)
	}

	// ─── WRITE PATCHED OUTPUT ─────────────────────────────────────────────────
	if err := os.WriteFile(*outFile, data, 0644); err != nil {
		log.Fatalf("write error: %v", err)
	}
	fmt.Printf("📦 Wrote patched binary to %s\n", *outFile)

	// ─── NEW HASH ─────────────────────────────────────────────────────────────
	newHash, err := computeHash(*outFile, *algo)
	if err != nil {
		log.Fatalf("cannot hash patched: %v", err)
	}
	fmt.Printf("✅ Patched  %s hash: %s → %s\n",
		filepath.Base(*outFile), *algo, newHash)
}
