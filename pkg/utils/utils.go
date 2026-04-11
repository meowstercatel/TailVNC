package utils

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
)

func generateHostname() string {
	// Generate a random hostname - a bit of entropy
	prefixes := []string{"web", "api", "cdn", "mail", "ftp", "db", "cache", "proxy", "gw", "vpn"}
	suffixes := []string{"srv", "node", "host", "box", "vm", "sys"}

	randBytes := make([]byte, 4)
	rand.Read(randBytes)

	prefixIdx := int(randBytes[0]) % len(prefixes)
	suffixIdx := int(randBytes[1]) % len(suffixes)
	num := int(randBytes[2])%100 + 1

	return fmt.Sprintf("%s-%s-%02d", prefixes[prefixIdx], suffixes[suffixIdx], num)
}

func GetSystemHostname() string {
	if hostName, err := os.Hostname(); err == nil {
		hostName = strings.Split(hostName, ".")[0]
		hostName = strings.ReplaceAll(hostName, "_", "-")
		if len(hostName) > 0 && len(hostName) <= 63 {
			return hostName
		}
	}

	return generateHostname()
}
