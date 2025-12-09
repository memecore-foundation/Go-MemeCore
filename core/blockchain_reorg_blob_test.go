// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
)

// TestWriteKnownBlockMissingBlobSidecars tests that writeKnownBlock correctly
// stores blob sidecars for Cancun+ blocks during chain reorg.
//
// Bug scenario (before fix):
// 1. Cancun fork activated
// 2. Chain reorg occurs, making new blocks canonical
// 3. writeKnownBlock() is called for the new canonical blocks
// 4. writeKnownBlock() did NOT store blob sidecars (bug)
// 5. Freezer tries to freeze block when HEAD - ImmutabilityThreshold reached
// 6. Error: 'block blobs missing, can't freeze block N'
//
// Fix: Added WriteBlobSidecars call in writeKnownBlock() for Cancun+ blocks
func TestWriteKnownBlockMissingBlobSidecars(t *testing.T) {
	// Create chain config with Cancun enabled (based on genesis_pectra.json)
	shanghaiTime := uint64(0)
	cancunTime := uint64(0)
	config := &params.ChainConfig{
		ChainID:             big.NewInt(12345),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ShanghaiTime:        &shanghaiTime,
		CancunTime:          &cancunTime,
		Ethash:              new(params.EthashConfig),
		BlobScheduleConfig: &params.BlobScheduleConfig{
			Cancun: &params.BlobConfig{
				Target:         3,
				Max:            6,
				UpdateFraction: 3338477,
			},
		},
	}

	// Create genesis
	gspec := &Genesis{
		Config:  config,
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}

	// Initialize database and blockchain
	db := rawdb.NewMemoryDatabase()
	tdb := triedb.NewDatabase(db, triedb.HashDefaults)
	genesis := gspec.MustCommit(db, tdb)

	// Create blockchain
	chain, err := NewBlockChain(db, nil, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	// Note: Skipping chain.Stop() to avoid nil pointer issues in test environment

	// Generate a block with empty sidecars
	blocks, _ := GenerateChain(config, genesis, ethash.NewFaker(), db, 1, func(i int, gen *BlockGen) {
		// Empty block, no transactions
	})

	block := blocks[0]

	// Attach empty sidecars to the block (simulating a Cancun block)
	emptySidecars := make(types.BlobSidecars, 0)
	blockWithSidecars := block.WithSidecars(emptySidecars)

	// Verify sidecars are attached
	if blockWithSidecars.Sidecars() == nil {
		t.Fatal("Block should have sidecars attached")
	}

	// Test: Call writeKnownBlock directly
	// First, we need to write the block body to DB (simulating it was received from peer)
	rawdb.WriteBlock(db, blockWithSidecars)

	// Now call writeKnownBlock to verify it stores blob sidecars
	err = chain.writeKnownBlock(blockWithSidecars)
	if err != nil {
		t.Fatalf("writeKnownBlock failed: %v", err)
	}

	// Check if blob sidecars were stored
	storedSidecars := rawdb.ReadBlobSidecarsRLP(db, blockWithSidecars.Hash(), blockWithSidecars.NumberU64())

	// Verify blob sidecars are stored correctly
	if len(storedSidecars) == 0 {
		t.Fatal("writeKnownBlock should store blob sidecars for Cancun+ blocks")
	}
	t.Logf("writeKnownBlock stores blob sidecars correctly (len=%d)", len(storedSidecars))
}

// TestBlobSidecarsRLPEncoding tests the RLP encoding behavior of blob sidecars
func TestBlobSidecarsRLPEncoding(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	blockHash := common.Hash{1, 2, 3}
	blockNum := uint64(100)

	// Test 1: Write nil sidecars
	var nilSidecars types.BlobSidecars
	rawdb.WriteBlobSidecars(db, blockHash, blockNum, nilSidecars)
	nilResult := rawdb.ReadBlobSidecarsRLP(db, blockHash, blockNum)

	if len(nilResult) != 1 || nilResult[0] != 0xc0 {
		t.Errorf("nil sidecars should encode to c0, got %x", nilResult)
	}

	// Test 2: Write empty sidecars
	blockHash2 := common.Hash{4, 5, 6}
	emptySidecars := make(types.BlobSidecars, 0)
	rawdb.WriteBlobSidecars(db, blockHash2, blockNum, emptySidecars)
	emptyResult := rawdb.ReadBlobSidecarsRLP(db, blockHash2, blockNum)

	if len(emptyResult) != 1 || emptyResult[0] != 0xc0 {
		t.Errorf("empty sidecars should encode to c0, got %x", emptyResult)
	}

	// Test 3: Read non-existent sidecars
	blockHash3 := common.Hash{7, 8, 9}
	notWrittenResult := rawdb.ReadBlobSidecarsRLP(db, blockHash3, blockNum)

	if len(notWrittenResult) != 0 {
		t.Errorf("Unwritten sidecars should return empty slice, got %x", notWrittenResult)
	}

	// Summary
	t.Log("RLP Encoding Results:")
	t.Logf("  nil sidecars    → %x (len=%d)", nilResult, len(nilResult))
	t.Logf("  empty sidecars  → %x (len=%d)", emptyResult, len(emptyResult))
	t.Logf("  not written     → %x (len=%d)", notWrittenResult, len(notWrittenResult))
	t.Log("")
	t.Log("Key insight: freezeRange() checks len(sidecars) == 0")
	t.Log("  - Written nil/empty → len=1 (c0) → PASS")
	t.Log("  - Not written       → len=0      → FAIL with 'block blobs missing'")
}

// TestFreezerBlobSidecarsCheck tests the exact condition that freezeRange checks
func TestFreezerBlobSidecarsCheck(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	testCases := []struct {
		name          string
		setup         func(hash common.Hash, num uint64)
		expectFailure bool
	}{
		{
			name: "sidecars written (nil)",
			setup: func(hash common.Hash, num uint64) {
				var nilSidecars types.BlobSidecars
				rawdb.WriteBlobSidecars(db, hash, num, nilSidecars)
			},
			expectFailure: false,
		},
		{
			name: "sidecars written (empty)",
			setup: func(hash common.Hash, num uint64) {
				emptySidecars := make(types.BlobSidecars, 0)
				rawdb.WriteBlobSidecars(db, hash, num, emptySidecars)
			},
			expectFailure: false,
		},
		{
			name: "sidecars NOT written (bug scenario)",
			setup: func(hash common.Hash, num uint64) {
				// Do nothing - simulates writeKnownBlock not writing sidecars
			},
			expectFailure: true,
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash := common.Hash{byte(i + 10)}
			num := uint64(100 + i)

			tc.setup(hash, num)

			// This is the exact check from freezeRange() in chain_freezer.go:435
			sidecars := rawdb.ReadBlobSidecarsRLP(db, hash, num)
			wouldFail := len(sidecars) == 0

			if wouldFail != tc.expectFailure {
				t.Errorf("Expected failure=%v, got failure=%v (sidecars len=%d)",
					tc.expectFailure, wouldFail, len(sidecars))
			}

			if wouldFail {
				t.Logf("[FAIL] Would fail: 'block blobs missing, can't freeze block %d'", num)
			} else {
				t.Logf("[PASS] Would pass: sidecars found (len=%d)", len(sidecars))
			}
		})
	}
}
