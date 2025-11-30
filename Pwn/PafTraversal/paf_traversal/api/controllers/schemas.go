package controllers

type DownloadRequest struct {
	Filename string `json:"filename" binding:"required"`
}

type UploadRequest struct {
	Filename string `json:"filename" binding:"required"`
	Content  string `json:"content" binding:"required"`
}

type DeleteRequest struct {
	Filename string `json:"filename" binding:"required"`
}

type BruteforceRequest struct {
	Algorithm int    `json:"algorithm" default:"0"`
	Hash      string `json:"hash" binding:"required"`
	Wordlist  string `json:"wordlist" binding:"required"`
}
