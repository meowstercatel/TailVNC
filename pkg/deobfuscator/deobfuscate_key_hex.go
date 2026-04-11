package deobfuscator

import "encoding/hex"

var xorKey = []byte("r4!kV#9xLp")

func DeobfuscateAuthKey(obfuscatedKey string) string {
	if obfuscatedKey == "" {
		return ""
	}
	data, err := hex.DecodeString(obfuscatedKey)
	if err != nil {
		return ""
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ xorKey[i%len(xorKey)]
	}
	return string(result)
}
