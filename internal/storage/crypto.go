package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

const (
	encFileVersion = 1
	saltLen        = 16
	nonceLen       = 12
	keyLen         = 32 // AES-256

	// Argon2id parameters (OWASP recommended minimum)
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4

	headerLen = 1 + saltLen + nonceLen // version + salt + nonce

	ioChunkSize = 4 * 1024 * 1024 // 4 MB chunks for progress reporting
)

var (
	ErrWrongPassword = errors.New("wrong password or corrupted file")
	ErrInvalidFile   = errors.New("invalid encrypted file format")
)

// CryptoProgress reports the current state of an encrypt/decrypt operation.
type CryptoProgress struct {
	Phase   string  `json:"phase"`   // "reading", "deriving", "encrypting"/"decrypting", "writing", "done"
	Percent float64 `json:"percent"` // 0-100
	SizeMB  float64 `json:"sizeMB"`  // total file size in MB
}

// ProgressFunc is called during encrypt/decrypt to report progress.
type ProgressFunc func(CryptoProgress)

// DeriveKey derives an AES-256 key from a password and salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
}

// EncryptFile encrypts srcPath to dstPath using AES-256-GCM with a key derived from password.
// Uses atomic write (tmp file + rename) for crash safety.
// File format: [1 byte version][16 bytes salt][12 bytes nonce][ciphertext + GCM tag]
func EncryptFile(srcPath, dstPath, password string) error {
	return EncryptFileWithProgress(srcPath, dstPath, password, nil)
}

// EncryptFileWithProgress is like EncryptFile but reports progress.
func EncryptFileWithProgress(srcPath, dstPath, password string, progress ProgressFunc) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	sizeMB := float64(info.Size()) / (1024 * 1024)

	// Phase 1: Read (0-35%)
	emit(progress, "reading", 0, sizeMB)
	plaintext, err := readFileChunked(srcPath, info.Size(), func(pct float64) {
		emit(progress, "reading", pct*35, sizeMB)
	})
	if err != nil {
		return fmt.Errorf("read source: %w", err)
	}

	// Phase 2: Key derivation (35-50%)
	emit(progress, "deriving", 35, sizeMB)
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	key := DeriveKey(password, salt)
	emit(progress, "deriving", 50, sizeMB)

	// Phase 3: Encrypt (50-75%)
	emit(progress, "encrypting", 50, sizeMB)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	plaintext = nil // release memory
	emit(progress, "encrypting", 75, sizeMB)

	// Phase 4: Write (75-100%)
	header := make([]byte, headerLen)
	header[0] = encFileVersion
	copy(header[1:], salt)
	copy(header[1+saltLen:], nonce)

	tmpPath := dstPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := f.Write(header); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write header: %w", err)
	}
	err = writeChunked(f, ciphertext, func(pct float64) {
		emit(progress, "writing", 75+pct*25, sizeMB)
	})
	if err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write ciphertext: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename to final: %w", err)
	}

	emit(progress, "done", 100, sizeMB)
	return nil
}

// DecryptFile decrypts srcPath to dstPath. Returns ErrWrongPassword if decryption fails.
// Uses atomic write for crash safety.
func DecryptFile(srcPath, dstPath, password string) error {
	return DecryptFileWithProgress(srcPath, dstPath, password, nil)
}

// DecryptFileWithProgress is like DecryptFile but reports progress.
func DecryptFileWithProgress(srcPath, dstPath, password string, progress ProgressFunc) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("stat encrypted file: %w", err)
	}
	sizeMB := float64(info.Size()) / (1024 * 1024)

	// Phase 1: Read (0-35%)
	emit(progress, "reading", 0, sizeMB)
	data, err := readFileChunked(srcPath, info.Size(), func(pct float64) {
		emit(progress, "reading", pct*35, sizeMB)
	})
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	if int64(len(data)) < int64(headerLen) {
		return ErrInvalidFile
	}

	version := data[0]
	if version != encFileVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidFile, version)
	}

	salt := data[1 : 1+saltLen]
	nonce := data[1+saltLen : headerLen]
	ciphertext := data[headerLen:]

	// Phase 2: Key derivation (35-50%)
	emit(progress, "deriving", 35, sizeMB)
	key := DeriveKey(password, salt)
	emit(progress, "deriving", 50, sizeMB)

	// Phase 3: Decrypt (50-75%)
	emit(progress, "decrypting", 50, sizeMB)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ErrWrongPassword
	}
	data = nil // release memory
	emit(progress, "decrypting", 75, sizeMB)

	// Phase 4: Write (75-100%)
	tmpPath := dstPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	err = writeChunked(f, plaintext, func(pct float64) {
		emit(progress, "writing", 75+pct*25, sizeMB)
	})
	if err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write decrypted file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename decrypted file: %w", err)
	}

	emit(progress, "done", 100, sizeMB)
	return nil
}

// --- I/O helpers with progress ---

func emit(fn ProgressFunc, phase string, percent, sizeMB float64) {
	if fn != nil {
		fn(CryptoProgress{Phase: phase, Percent: percent, SizeMB: sizeMB})
	}
}

func readFileChunked(path string, size int64, onProgress func(pct float64)) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, size)
	var read int64
	for read < size {
		n := int64(ioChunkSize)
		if read+n > size {
			n = size - read
		}
		_, err := io.ReadFull(f, buf[read:read+n])
		if err != nil {
			return nil, err
		}
		read += n
		if onProgress != nil && size > 0 {
			onProgress(float64(read) / float64(size))
		}
	}
	return buf, nil
}

func writeChunked(f *os.File, data []byte, onProgress func(pct float64)) error {
	total := len(data)
	written := 0
	for written < total {
		end := written + ioChunkSize
		if end > total {
			end = total
		}
		n, err := f.Write(data[written:end])
		if err != nil {
			return err
		}
		written += n
		if onProgress != nil && total > 0 {
			onProgress(float64(written) / float64(total))
		}
	}
	return nil
}

// EncryptedFileExists checks if an encrypted version of dbPath exists.
func EncryptedFileExists(dbPath string) bool {
	_, err := os.Stat(dbPath + ".enc")
	return err == nil
}
