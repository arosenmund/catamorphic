package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
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

func backupFile(src string) (string, error) {
	bak := src + ".bak"
	if err := ioutil.WriteFile(bak, mustReadAll(src), 0644); err != nil {
		return "", err
	}
	return bak, nil
}

func mustReadAll(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("unable to read %s: %v", path, err)
	}
	return data
}

func main() {
	// ----- CLI flags -----
	inFile := flag.String("in", "", "input Go-built binary (required)")
	outFile := flag.String("out", "", "output file path (required)")
	algo := flag.String("hash", "md5", "hash algorithm: md5 or sha256")
	keyLen := flag.Int("keylen", 16, "length of random key to inject")
	offset := flag.Int("offset", -1, "byte offset to patch at; -1 = append")
	replaceVer := flag.String("replace-ver", "",
		"overwrite Go version string in-place (auto-pads/truncates to match original length)")
	doBackup := flag.Bool("backup", false, "create a .bak of the original before patching")
	flag.Parse()

	if *inFile == "" || *outFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// ----- Optional backup -----
	if *doBackup {
		bak, err := backupFile(*inFile)
		if err != nil {
			log.Fatalf("🔒 backup failed: %v", err)
		}
		fmt.Printf("🔒 Backed up original to %s\n", bak)
	}

	// ----- Original hash -----
	origHash, err := computeHash(*inFile, *algo)
	if err != nil {
		log.Fatalf("cannot hash original: %v", err)
	}
	fmt.Printf("📝 Original %s hash: %s → %s\n",
		filepath.Base(*inFile), *algo, origHash)

	// ----- Read entire binary -----
	data, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("read error: %v", err)
	}

	// ----- Detect Go version & find its offset -----
	var verOffset, verLen int
	if info, err := buildinfo.ReadFile(*inFile); err != nil {
		fmt.Printf("⚠️  No build info: %v\n", err)
		if *replaceVer != "" {
			log.Fatalf("no Go version to replace in this binary")
		}
	} else {
		origVer := info.GoVersion
		verLen = len(origVer)
		fmt.Printf("🔍 Detected Go version: %s\n", origVer)
		verOffset = bytes.Index(data, []byte(origVer))
		if verOffset >= 0 {
			fmt.Printf("⛳ Version string offset: %d (0x%X)\n", verOffset, verOffset)
		} else {
			fmt.Println("❓ Version string not found in raw bytes")
			if *replaceVer != "" {
				log.Fatalf("cannot replace version: original string missing")
			}
		}
	}

	// ----- Overwrite Go version if requested (auto pad/truncate) -----
	if *replaceVer != "" {
		if verOffset < 0 {
			log.Fatalf("no version offset to overwrite")
		}
		// Pad or truncate to exact length
		rep := *replaceVer
		if len(rep) < verLen {
			// pad with null bytes so following data stays intact
			rep = rep + strings.Repeat("\x00", verLen-len(rep))
		} else if len(rep) > verLen {
			rep = rep[:verLen]
		}
		copy(data[verOffset:verOffset+verLen], []byte(rep))
		fmt.Printf("🔄 Overwrote version at offset %d with: %q\n", verOffset, rep)
	}

	// ----- Generate & inject random key -----
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

	// ----- Write patched output -----
	if err := ioutil.WriteFile(*outFile, data, 0644); err != nil {
		log.Fatalf("write error: %v", err)
	}
	fmt.Printf("📦 Wrote patched binary to %s\n", *outFile)

	// ----- New hash -----
	newHash, err := computeHash(*outFile, *algo)
	if err != nil {
		log.Fatalf("cannot hash patched: %v", err)
	}
	fmt.Printf("✅ Patched  %s hash: %s → %s\n",
		filepath.Base(*outFile), *algo, newHash)
}
