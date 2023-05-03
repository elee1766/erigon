package raw

type MigratorFunc func(b *BeaconState)

type ViewFunc[T any] func(b *BeaconState) T
type ViewIdxFunc[T any] func(b *BeaconState, idx int) T
