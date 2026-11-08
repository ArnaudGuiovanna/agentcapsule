package operatorconfig

import (
	"path/filepath"
	"strings"
)

// KeyFiles is a repeatable operator flag containing IDs and file paths, never
// secret key bytes. Every referenced file is checked by ReadPrivate.
type KeyFiles map[string]string

func (k *KeyFiles) String() string { return "<private key files>" }
func (k *KeyFiles) Set(value string) error {
	id, path, ok := strings.Cut(value, "=")
	if !ok || id == "" || len(id) > 100 || !filepath.IsAbs(path) {
		return ErrPrivateFile
	}
	if *k == nil {
		*k = make(KeyFiles)
	}
	if _, exists := (*k)[id]; exists {
		return ErrPrivateFile
	}
	(*k)[id] = path
	return nil
}
func (k KeyFiles) Read() (map[string][]byte, error) {
	keys := make(map[string][]byte)
	for id, path := range k {
		key, err := ReadPrivate(path, 32)
		if err != nil {
			ClearKeys(keys)
			return nil, ErrPrivateFile
		}
		keys[id] = key
	}
	return keys, nil
}
func ClearKeys(keys map[string][]byte) {
	for _, key := range keys {
		clear(key)
	}
}
