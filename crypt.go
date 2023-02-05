package secretvalue

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Encryption/decryption of secrets. This code is heavily based upon Pulumi Go SDK:
// https://github.com/pulumi/pulumi/blob/master/sdk/go/common/resource/config/crypt.go

// Encrypter encrypts plaintext into its encrypted ciphertext.
type Encrypter interface {
	EncryptValue(plaintext string) (string, error)
}

// Decrypter decrypts encrypted ciphertext to its plaintext representation.
type Decrypter interface {
	DecryptValue(ciphertext string) (string, error)
}

// Crypter can both encrypt and decrypt values.
type Crypter interface {
	Encrypter
	Decrypter
}

// A nopCrypter simply returns the ciphertext as-is.
type nopCrypter struct{}

var (
	NopDecrypter Decrypter = nopCrypter{}
	NopEncrypter Encrypter = nopCrypter{}
)

func (nopCrypter) DecryptValue(ciphertext string) (string, error) {
	return ciphertext, nil
}

func (nopCrypter) EncryptValue(plaintext string) (string, error) {
	return plaintext, nil
}

// NewSymmetricCrypter creates a crypter that encrypts and decrypts values using AES-256-GCM.  The nonce is stored with
// the value itself as a pair of base64 values separated by a colon and a version tag `v1` is prepended.
func NewSymmetricCrypter(key []byte) (Crypter, error) {
	if len(key) == SymmetricCrypterKeyBytes {
		return &symmetricCrypter{key}, nil
	} else {
		return nil, errors.New("AES-256-GCM needs a 32 byte key")
	}
}

// SymmetricCrypterKeyBytes is the required key size in bytes.
const SymmetricCrypterKeyBytes = 32

type symmetricCrypter struct {
	key []byte
}

func (s symmetricCrypter) EncryptValue(value string) (string, error) {
	secret, nonce, err := encryptAES256GCGM(value, s.key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v1:%s:%s",
		base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(secret)), nil
}

func (s symmetricCrypter) DecryptValue(value string) (string, error) {
	vals := strings.Split(value, ":")
	if len(vals) != 3 {
		return "", errors.New("bad value")
	}
	if vals[0] != "v1" {
		return "", errors.New("unknown value version")
	}
	nonce, err := base64.StdEncoding.DecodeString(vals[1])
	if err != nil {
		return "", fmt.Errorf("bad value: %w", err)
	}
	enc, err := base64.StdEncoding.DecodeString(vals[2])
	if err != nil {
		return "", fmt.Errorf("bad value: %w", err)
	}
	return decryptAES256GCM(enc, s.key, nonce)
}

// encryptAES256GCGM returns the ciphertext and the generated nonce
func encryptAES256GCGM(plaintext string, key []byte) ([]byte, []byte, error) {
	if len(key) != SymmetricCrypterKeyBytes {
		return nil, nil, errors.New("AES-256-GCM needs a 32 byte key")
	}
	nonce := make([]byte, 12)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("could not read from system random source: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating AES-GCM cipher: %w", err)
	}
	msg := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	return msg, nonce, nil
}

func decryptAES256GCM(ciphertext []byte, key []byte, nonce []byte) (string, error) {
	if len(key) != SymmetricCrypterKeyBytes {
		return "", errors.New("AES-256-GCM needs a 32 byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating AES-GCM cipher: %w", err)
	}
	msg, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	return string(msg), err
}
