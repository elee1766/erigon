package consensus_tests

import (
	"io/fs"
	"os"
	"testing"

	"github.com/ledgerwatch/erigon/cl/clparams"
	"github.com/ledgerwatch/erigon/cmd/ef-tests-cl/spectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ForksFork = spectest.HandlerFunc(func(t *testing.T, root fs.FS, c spectest.TestCase) (err error) {

	preState, err := spectest.ReadBeaconState(root, c.Version()-1, spectest.PreSsz)
	require.NoError(t, err)

	postState, err := spectest.ReadBeaconState(root, c.Version(), spectest.PostSsz)
	expectedError := os.IsNotExist(err)
	if !expectedError {
		require.NoError(t, err)
	}
	switch preState.Version() {
	case clparams.Phase0Version:
		err = preState.UpgradeToAltair()
	case clparams.AltairVersion:
		err = preState.UpgradeToBellatrix()
	case clparams.BellatrixVersion:
		err = preState.UpgradeToCapella()
	default:
		panic("unsupported version")
	}
	if expectedError {
		assert.Error(t, err)
	}

	haveRoot, err := preState.HashSSZ()
	assert.NoError(t, err)

	expectedRoot, err := postState.HashSSZ()
	assert.NoError(t, err)

	assert.EqualValues(t, haveRoot, expectedRoot, "state root")

	return nil
})