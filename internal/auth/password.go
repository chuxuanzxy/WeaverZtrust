package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	hashVersion = "pbkdf2-sha256"
	iterations  = 120000
	saltBytes   = 16
	keyBytes    = 32
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, iterations, keyBytes)
	return fmt.Sprintf("%s$%d$%s$%s",
		hashVersion,
		iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashVersion {
		return false
	}
	rounds, err := strconv.Atoi(parts[1])
	if err != nil || rounds <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, rounds, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, rounds, length int) []byte {
	hashLen := sha256.Size
	numBlocks := (length + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		u := prf(password, appendInt(salt, block))
		t := append([]byte(nil), u...)
		for i := 1; i < rounds; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:length]
}

func prf(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func appendInt(prefix []byte, value int) []byte {
	out := make([]byte, len(prefix)+4)
	copy(out, prefix)
	out[len(prefix)] = byte(value >> 24)
	out[len(prefix)+1] = byte(value >> 16)
	out[len(prefix)+2] = byte(value >> 8)
	out[len(prefix)+3] = byte(value)
	return out
}
