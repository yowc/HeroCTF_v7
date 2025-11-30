package controllers

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	FIFO_IN         = "/tmp/cracker.in"
	FIFO_OUT        = "/tmp/cracker.out"
	DEFAULT_TIMEOUT = 30 * time.Second
	readPollDelay   = 50 * time.Millisecond
)

func writeRequest(algo int, hashHex, wordlist string) error {
	data := []byte(fmt.Sprintf("%d\n%s\n%s\n", algo, hashHex, wordlist))

	fd, err := syscall.Open(FIFO_IN, syscall.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", FIFO_IN, err)
	}

	total := 0
	for total < len(data) {
		n, werr := syscall.Write(fd, data[total:])
		if werr != nil {
			_ = syscall.Close(fd)
			return fmt.Errorf("error writing request to %s: %w", FIFO_IN, werr)
		}
		if n == 0 {
			_ = syscall.Close(fd)
			return fmt.Errorf("write returned 0")
		}
		total += n
	}
	_ = syscall.Close(fd)
	return nil
}

func readResponse(timeout time.Duration) (string, error) {
	start := time.Now()
	deadline := start.Add(timeout)

	fd, err := syscall.Open(FIFO_OUT, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open %s for reading: %w", FIFO_OUT, err)
	}
	defer syscall.Close(fd)

	bufio.NewReader(os.NewFile(uintptr(fd), FIFO_OUT))
	var buf bytes.Buffer

	for time.Now().Before(deadline) {
		chunk := make([]byte, 4096)
		n, rerr := syscall.Read(fd, chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if idx := bytes.IndexByte(buf.Bytes(), '\n'); idx >= 0 {
				line := buf.Bytes()[:idx]
				line = bytes.TrimRight(line, "\r\n")
				return string(line), nil
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, syscall.EAGAIN) && !errors.Is(rerr, syscall.EWOULDBLOCK) {
				return "", fmt.Errorf("error reading from %s: %w", FIFO_OUT, rerr)
			}
		}
		time.Sleep(readPollDelay)
	}

	return "", fmt.Errorf("timeout waiting for response from %s", FIFO_OUT)
}

func requestAndWait(algo int, hashHex, wordlist string, timeout time.Duration) (string, error) {
	if err := writeRequest(algo, hashHex, wordlist); err != nil {
		return "", err
	}

	resp, err := readResponse(timeout)
	if err != nil {
		return "", err
	}
	return resp, nil
}

func StartBruteforce(c *gin.Context) {
	wordlistDir := getWordlistDir()

	json := BruteforceRequest{}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if json.Algorithm < 0 || json.Algorithm > 99 {
		c.JSON(400, gin.H{"error": "algorithm should be between 0 and 99"})
		return
	}

	filePath := filepath.Join(wordlistDir, path.Base(json.Wordlist))
	resp, err := requestAndWait(json.Algorithm, json.Hash, filePath, DEFAULT_TIMEOUT)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	successPrefix := "SUCCESS:"
	errorPrefix := "ERROR:"

	switch {
	case len(resp) >= len(successPrefix) && resp[:len(successPrefix)] == successPrefix:
		pw := resp[len(successPrefix):]
		c.JSON(http.StatusOK, gin.H{
			"message": "Password: " + pw,
		})
		return
	case len(resp) >= len(errorPrefix) && resp[:len(errorPrefix)] == errorPrefix:
		errorMsg := resp[len(errorPrefix):]
		c.JSON(http.StatusOK, gin.H{
			"error": errorMsg,
		})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{
		"error": "Internal server error: unexpected response",
	})
}
