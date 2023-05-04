package merkle_tree

import "github.com/ledgerwatch/erigon-lib/common"

func JoinHashes(c ...common.Hash) []byte {
	o := make([]byte, 0, len(c)*32)
	for _, v := range c {
		o = append(o, v[:]...)
	}
	return o
}
func JoinB32(c [][32]byte) []byte {
	o := make([]byte, 0, len(c)*32)
	for _, v := range c {
		o = append(o, v[:]...)
	}
	return o
}
