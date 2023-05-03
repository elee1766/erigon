package merkle_tree

import (
	"encoding/binary"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
)

// Uint64Root retrieves the root hash of a uint64 value by converting it to a byte array and returning it as a hash.
func Uint64Root(val uint64) libcommon.Hash {
	var root libcommon.Hash
	binary.LittleEndian.PutUint64(root[:], val)
	return root
}

func BoolRoot(b bool) (root libcommon.Hash) {
	if b {
		root[0] = 1
	}
	return
}

func SignatureRoot(signature [96]byte) ([]byte, error) {
	return ArraysRoot(signature[:], 4)
}

func PublicKeyRoot(key [48]byte) ([]byte, error) {
	var lastByte [32]byte
	copy(lastByte[:], key[32:])
	return ArraysRoot(append(
		key[:33],
		make([]byte, 31)...,
	), 2)
}
