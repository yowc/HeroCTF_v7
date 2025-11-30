# Paf Traversal

### Category

Pwn

### Difficulty

Easy

### Tags

- go
- c
- fifo

### Author

xanhacks

### Description

Your mission is to audit a high-performance hash-cracking platform. It achieves its speed by combining a Go-based API server with a C-powered hash-cracking service.

Deploy an instance at [https://deploy.heroctf.fr/](https://deploy.heroctf.fr/).

### Files

- [paf_traversal.zip](paf_traversal.zip)

### Write Up

See [solve.py](solve.py).

#### Leak via /proc/PID/maps

The `filePath` variable is vulnerable to Path Traveral, you can abuse it to read `/proc/<cracker_pid>/maps` and leak the libc base address.

```go
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
```

#### RCE via function pointer

The user-controlled `algo_type` is not validated against the bounds of the `hash_functions` array. That lets `compute_fn* hash_fn` be initialized using an out-of-range index, so `hash_fn` can end up pointing into user-controlled memory (the `hash_bin` buffer). Because `hash_bin` is populated from attacker-supplied hex via `from_hex`, an attacker can place an address there (for example, the address of libc's `system`).

```c
    int output_len = SHA256_DIGEST_LENGTH;
    switch (algo_type) {
        case 0: output_len = MD5_DIGEST_LENGTH; break;
        case 1: output_len = SHA_DIGEST_LENGTH; break;
        case 2: output_len = SHA256_DIGEST_LENGTH; break;
        default:
            fprintf(stderr, "Unsupported algorithm type: %d\n", algo_type);
            dprintf(outfd, "ERROR:unsupported algorithm type %d\n", algo_type);
            close(outfd);
    }

    compute_fn hash_functions[] = {
        compute_md5,
        compute_sha1,
        compute_sha256,
    };
    compute_fn* hash_fn = &hash_functions[algo_type];
	// ...
	from_hex(hash_str, (unsigned char *)hash_bin, output_len);
```

Later, when the program invokes `(*hash_fn)((const unsigned char *)pw, pwlen, output_bin)`, the first argument is the wordlist entry (`pw`) and is attacker-controlled, so a crafted wordlist line like `cp /app/flag_*.txt /app/api/assets/flag.txt` will be passed to `system`, resulting in remote code execution.

```c
    char pw[512];
    int found = 0;
    while (fgets(pw, sizeof(pw), wordlist)) {
        size_t pwlen = strcspn(pw, "\r\n");
        pw[pwlen] = '\0';
        if (pwlen == 0) continue;

        (*hash_fn)((const unsigned char *)pw, pwlen, output_bin);
		// ...
	}
```

### Flag

Hero{e9e2b63a0daa9ee41d2133b450425b2cd7c7510e5a28b655748456bd3f6e5c2a}