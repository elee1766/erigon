package merkle_tree

import "encoding/binary"

// PackUint64IntoChunks packs a list of uint64 values into 32 byte roots.
func PackUint64IntoChunks(vals []uint64) []byte {
	chunks := make([]byte, len(vals)*8)
	for i := 0; i < len(vals); i++ {
		byteIndex := i * 8
		binary.LittleEndian.PutUint64(chunks[byteIndex:byteIndex+8], vals[i])
	}
	return chunks
}

func PackSlashings(serializedItems [][]byte) ([]byte, error) {
	emptyChunk := [32]byte{}

	// If there are no items, return an empty chunk
	if len(serializedItems) == 0 {
		return emptyChunk[:], nil
	}

	// Flatten the list of items
	orderedItems := make([]byte, 0, len(serializedItems)*len(serializedItems[0]))
	for _, item := range serializedItems {
		orderedItems = append(orderedItems, item...)
	}

	// If the flattened list is empty, return an empty chunk
	if len(orderedItems) == 0 {
		return emptyChunk[:], nil
	}

	return orderedItems, nil
}
