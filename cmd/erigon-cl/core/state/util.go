package state

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

func copyLRU[K comparable, V any](dst *lru.Cache[K, V], src *lru.Cache[K, V]) *lru.Cache[K, V] {
	if dst == nil {
		dst = new(lru.Cache[K, V])
	}
	for _, key := range src.Keys() {
		val, has := src.Get(key)
		if !has {
			continue
		}
		dst.Add(key, val)
	}
	return dst
}
