package osint

import (
	"crypto/md5"
	"encoding/hex"
)

// md5Hex returns the lowercase hex MD5 of s. Gravatar keys avatars by the
// md5 of the trimmed, lower-cased email — this is a documented public scheme,
// not a security use of MD5.
func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // Gravatar's public keying scheme, not crypto.
	return hex.EncodeToString(sum[:])
}
