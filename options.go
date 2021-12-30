package gojwk

// Main Options for JWKS
type Options func(k *key)

// Storage define external storage for key save and load.
// Save method need for save when new key generated key
func Storage(s keyStorage) Options {
	return func(k *key) {
		k.storage = s
	}
}

// BitSize value
func BitSize(bitSize int) Options {
	return func(k *key) {
		k.bitSize = bitSize
	}
}
