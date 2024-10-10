package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"flag"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

func main() {
	password := flag.String("password", "", "photok password")
	backupFile := flag.String("file", "", "path to backup file")
	numWorkers := flag.Int("worker", 10, "number of workers")
	flag.Parse()

	var wg sync.WaitGroup

	jobs := make(chan *zip.File)

	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)

		go worker(*password, jobs, &wg)
	}

	r, err := zip.OpenReader(*backupFile)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".tn") && strings.HasSuffix(f.Name, ".photok") {
			jobs <- f
		}
	}

	close(jobs)

	wg.Wait()
}

func worker(password string, jobs <-chan *zip.File, wg *sync.WaitGroup) {
	defer wg.Done()

	key := photokKey(password)
	iv := photokIV(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		log.Fatal(err)
	}

	for file := range jobs {
		reader, err := file.Open()
		if err != nil {
			log.Fatal(err)
		}

		ciphertext, err := io.ReadAll(reader)
		if err != nil {
			log.Fatal(err)
		}

		plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
		if err != nil {
			log.Fatal(err)
		}

		if err := os.WriteFile(file.Name+".plaintext", plaintext, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func photokKey(password string) []byte {
	h := sha256.New()
	h.Write([]byte(password))

	return h.Sum(nil)
}

func photokIV(password string) []byte {
	iv := make([]byte, 16)
	for i := 0; i < 16 && i < len(password); i++ {
		iv[i] = password[i]
	}

	return iv
}
