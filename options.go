package gojwk

// Main Options for JWKS
type Options func(k *Key)

// Storage define external storage for Key save and load.
// Save method need for save when new Key generated Key
func Storage(s keyStorage) Options {
	return func(k *Key) {
		k.storage = s
	}
}

// BitSize value
func BitSize(bitSize int) Options {
	return func(k *Key) {
		k.bitSize = bitSize
	}
}
