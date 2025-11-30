package controllers

import (
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func HandleListWordlist(c *gin.Context) {
	wordlistDir := getWordlistDir()

	if err := os.MkdirAll(wordlistDir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	entries, err := os.ReadDir(wordlistDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}

	c.JSON(http.StatusOK, gin.H{"files": files})
}

func HandleDownloadWordlist(c *gin.Context) {
	wordlistDir := getWordlistDir()

	json := DownloadRequest{}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fileName := path.Base(json.Filename)
	filePath := filepath.Join(wordlistDir, json.Filename)

	f, err := os.Open(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"filename": fileName,
		"content":  string(data),
	})
}

func HandleUploadWordlist(c *gin.Context) {
	wordlistDir := getWordlistDir()

	if err := os.MkdirAll(wordlistDir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	json := UploadRequest{}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(json.Content) >= 10*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File content exceeds maximum allowed size of 10MB"})
		return
	}

	dstPath := filepath.Join(wordlistDir, path.Base(json.Filename))
	if err := os.WriteFile(dstPath, []byte(json.Content), 0o644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File successfully uploaded"})
}

func HandleDeleteWordlist(c *gin.Context) {
	wordlistDir := getWordlistDir()

	json := DeleteRequest{}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filePath := filepath.Join(wordlistDir, path.Base(json.Filename))
	if err := os.Remove(filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File successfully deleted"})
}
