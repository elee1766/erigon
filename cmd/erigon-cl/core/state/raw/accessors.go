package raw

import (
	"errors"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
)

// these are view functions that should only getters, but are here as common utilities for packages to use

var (
	ErrGetBlockRootAtSlotFuture = errors.New("GetBlockRootAtSlot: slot in the future")
)

// GetBlockRoot returns blook root at start of a given epoch
func (b *BeaconState) GetBlockRoot(epoch uint64) (libcommon.Hash, error) {
	return b.GetBlockRootAtSlot(epoch * b.BeaconConfig().SlotsPerEpoch)
}

// PreviousEpoch returns previous epoch.
func (b *BeaconState) PreviousEpoch() uint64 {
	epoch := b.Epoch()
	if epoch == 0 {
		return epoch
	}
	return epoch - 1
}

// GetTotalSlashingAmount return the sum of all slashings.
func (b *BeaconState) GetTotalSlashingAmount() (t uint64) {
	b.ForEachSlashingSegment(func(v uint64, idx, total int) bool {
		t += v
		return true
	})
	return
}

// GetTotalBalance return the sum of all balances within the given validator set.
func (b *BeaconState) GetTotalBalance(validatorSet []uint64) (uint64, error) {
	var (
		total uint64
	)
	for _, validatorIndex := range validatorSet {
		// Should be in bounds.
		delta, err := b.ValidatorEffectiveBalance(int(validatorIndex))
		if err != nil {
			return 0, err
		}
		total += delta
	}
	// Always minimum set to EffectiveBalanceIncrement
	if total < b.BeaconConfig().EffectiveBalanceIncrement {
		total = b.BeaconConfig().EffectiveBalanceIncrement
	}
	return total, nil
}

// GetEpochAtSlot gives the epoch for a certain slot
func (b *BeaconState) GetEpochAtSlot(slot uint64) uint64 {
	return slot / b.BeaconConfig().SlotsPerEpoch
}

// Epoch returns current epoch.
func (b *BeaconState) Epoch() uint64 {
	return b.GetEpochAtSlot(b.Slot())
}
