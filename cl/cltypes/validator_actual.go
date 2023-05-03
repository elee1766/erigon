package cltypes

import (
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/cl/cltypes/ssz"
	"github.com/ledgerwatch/erigon/cl/merkle_tree"
)

// Validator, contains if we were on bellatrix/alteir/phase0 and transition epoch.
type Validator struct {
	PublicKey                  [48]byte
	WithdrawalCredentials      common.Hash
	EffectiveBalance           uint64
	Slashed                    bool
	ActivationEligibilityEpoch uint64
	ActivationEpoch            uint64
	ExitEpoch                  uint64
	WithdrawableEpoch          uint64
	// This is all stuff used by phase0 state transition. It makes many operations faster.
	// Source attesters
	IsCurrentMatchingSourceAttester  bool
	IsPreviousMatchingSourceAttester bool
	// Target Attesters
	IsCurrentMatchingTargetAttester  bool
	IsPreviousMatchingTargetAttester bool
	// Head attesters
	IsCurrentMatchingHeadAttester  bool
	IsPreviousMatchingHeadAttester bool
	// MinInclusionDelay
	MinCurrentInclusionDelayAttestation  *PendingAttestation
	MinPreviousInclusionDelayAttestation *PendingAttestation
}

// DutiesAttested returns how many of its duties the validator attested and missed
func (v *Validator) DutiesAttested() (attested, missed uint64) {
	if v.Slashed {
		return 0, 3
	}
	if v.IsPreviousMatchingSourceAttester {
		attested++
	}
	if v.IsPreviousMatchingTargetAttester {
		attested++
	}
	if v.IsPreviousMatchingHeadAttester {
		attested++
	}
	missed = 3 - attested
	return
}
func (v *Validator) IsSlashable(epoch uint64) bool {
	return !v.Slashed && (v.ActivationEpoch <= epoch) && (epoch < v.WithdrawableEpoch)
}

func (v *Validator) EncodeSSZ(dst []byte) ([]byte, error) {
	buf := dst
	buf = append(buf, v.PublicKey[:]...)
	buf = append(buf, v.WithdrawalCredentials[:]...)
	buf = append(buf, ssz.Uint64SSZ(v.EffectiveBalance)...)
	buf = append(buf, ssz.BoolSSZ(v.Slashed))
	buf = append(buf, ssz.Uint64SSZ(v.ActivationEligibilityEpoch)...)
	buf = append(buf, ssz.Uint64SSZ(v.ActivationEpoch)...)
	buf = append(buf, ssz.Uint64SSZ(v.ExitEpoch)...)
	buf = append(buf, ssz.Uint64SSZ(v.WithdrawableEpoch)...)
	return buf, nil
}

func (v *Validator) DecodeSSZWithVersion(buf []byte, _ int) error {
	return v.DecodeSSZ(buf)
}

func (v *Validator) DecodeSSZ(buf []byte) error {
	if len(buf) < v.EncodingSizeSSZ() {
		return ssz.ErrLowBufferSize
	}
	copy(v.PublicKey[:], buf)
	copy(v.WithdrawalCredentials[:], buf[48:])
	v.EffectiveBalance = ssz.UnmarshalUint64SSZ(buf[80:])
	v.Slashed = buf[88] == 1
	v.ActivationEligibilityEpoch = ssz.UnmarshalUint64SSZ(buf[89:])
	v.ActivationEpoch = ssz.UnmarshalUint64SSZ(buf[97:])
	v.ExitEpoch = ssz.UnmarshalUint64SSZ(buf[105:])
	v.WithdrawableEpoch = ssz.UnmarshalUint64SSZ(buf[113:])
	return nil
}

func (v *Validator) EncodingSizeSSZ() int {
	return 121
}

func (v *Validator) HashSSZ() ([32]byte, error) {
	var (
		leaves = make([][32]byte, 8)
		err    error
	)

	leaves[0], err = merkle_tree.PublicKeyRoot(v.PublicKey)
	if err != nil {
		return [32]byte{}, err
	}
	leaves[1] = v.WithdrawalCredentials
	leaves[2] = merkle_tree.Uint64Root(v.EffectiveBalance)
	leaves[3] = merkle_tree.BoolRoot(v.Slashed)
	leaves[4] = merkle_tree.Uint64Root(v.ActivationEligibilityEpoch)
	leaves[5] = merkle_tree.Uint64Root(v.ActivationEpoch)
	leaves[6] = merkle_tree.Uint64Root(v.ExitEpoch)
	leaves[7] = merkle_tree.Uint64Root(v.WithdrawableEpoch)
	return merkle_tree.ArraysRoot(leaves, 8)
}

// Active returns if validator is active for given epoch
func (v *Validator) Active(epoch uint64) bool {
	return v.ActivationEpoch <= epoch && epoch < v.ExitEpoch
}

func (v *Validator) Copy() *Validator {
	copied := *v
	return &copied
}
