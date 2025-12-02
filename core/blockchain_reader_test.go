package core

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

// makeBlkSidecars creates n blob sidecars with nPerTx blobs each
func makeBlkSidecars(n, nPerTx int) []*types.BlobTxSidecar {
	if n <= 0 {
		return nil
	}
	ret := make([]*types.BlobTxSidecar, n)
	for i := 0; i < n; i++ {
		blobs := make([]kzg4844.Blob, nPerTx)
		commitments := make([]kzg4844.Commitment, nPerTx)
		proofs := make([]kzg4844.Proof, nPerTx)
		for j := 0; j < nPerTx; j++ {
			io.ReadFull(rand.Reader, blobs[j][:])
			commitments[j], _ = kzg4844.BlobToCommitment(&blobs[j])
			proofs[j], _ = kzg4844.ComputeBlobProof(&blobs[j], commitments[j])
		}
		ret[i] = &types.BlobTxSidecar{
			Blobs:       blobs,
			Commitments: commitments,
			Proofs:      proofs,
		}
	}
	return ret
}

// TestGetSidecarsByHash tests the GetSidecarsByHash function with cache-first pattern
func TestGetSidecarsByHash(t *testing.T) {
	var (
		db      = rawdb.NewMemoryDatabase()
		gspec   = &Genesis{Config: params.TestChainConfig}
		genesis = gspec.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))
	)

	// Create a blockchain with Cancun enabled
	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme("hash"), gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	// Create test blob sidecars
	genBlobs := makeBlkSidecars(1, 2)
	blobHashes := []common.Hash{
		common.HexToHash("0x34ec6e64f9cda8fe0451a391e4798085a3ef51a65ed1bfb016e34fc1a2028f8f"),
		common.HexToHash("0xb9a412e875f29fac436acde234f954e91173c4cf79814f6dcf630d8a6345747f"),
	}

	// Create a blob transaction
	tx1 := types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		Value:      uint256.NewInt(0),
		Data:       nil,
		BlobFeeCap: uint256.NewInt(1),
		BlobHashes: blobHashes,
		Sidecar:    genBlobs[0],
		V:          uint256.NewInt(0),
		R:          uint256.NewInt(0),
		S:          uint256.NewInt(0),
	})

	// Create a block with blob transaction
	blockHash := common.BytesToHash([]byte{0x01, 0x02})
	blockNum := uint64(1)

	// Test 1: Non-existent block should return nil
	sidecars := chain.GetSidecarsByHash(common.Hash{})
	if sidecars != nil {
		t.Fatalf("Expected nil for non-existent block, got %v", sidecars)
	}

	// Test 2: Write header and blob sidecars
	header := &types.Header{
		Number:     big.NewInt(int64(blockNum)),
		ParentHash: genesis.Hash(),
		Difficulty: big.NewInt(1),
		GasLimit:   8000000,
		GasUsed:    0,
		Time:       genesis.Time() + 10,
	}
	rawdb.WriteHeader(db, header)
	rawdb.WriteCanonicalHash(db, blockHash, blockNum)
	rawdb.WriteHeaderNumber(db, blockHash, blockNum)

	expectedSidecars := types.BlobSidecars{types.NewBlobSidecarFromTx(tx1)}
	rawdb.WriteBlobSidecars(db, blockHash, blockNum, expectedSidecars)

	// Test 3: First call should read from DB and populate cache
	sidecars = chain.GetSidecarsByHash(blockHash)
	if sidecars == nil {
		t.Fatalf("Expected sidecars, got nil")
	}
	if len(sidecars) != len(expectedSidecars) {
		t.Fatalf("Expected %d sidecars, got %d", len(expectedSidecars), len(sidecars))
	}

	// Test 4: Second call should hit cache (verify cache-first pattern)
	// We can't directly test cache hit without instrumentation, but we verify
	// the function returns the same result
	sidecars2 := chain.GetSidecarsByHash(blockHash)
	if sidecars2 == nil {
		t.Fatalf("Expected cached sidecars, got nil")
	}
	if len(sidecars2) != len(expectedSidecars) {
		t.Fatalf("Expected %d cached sidecars, got %d", len(expectedSidecars), len(sidecars2))
	}

	// Test 5: Verify sidecar content matches
	if len(sidecars[0].Blobs) != len(genBlobs[0].Blobs) {
		t.Fatalf("Blob count mismatch: got %d, want %d", len(sidecars[0].Blobs), len(genBlobs[0].Blobs))
	}
}

// TestGetSidecarsByHashCacheFirst verifies cache is checked before DB access
func TestGetSidecarsByHashCacheFirst(t *testing.T) {
	var (
		db      = rawdb.NewMemoryDatabase()
		gspec   = &Genesis{Config: params.TestChainConfig}
		genesis = gspec.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))
	)

	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme("hash"), gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	// Create test data
	blockHash := common.BytesToHash([]byte{0x03, 0x04})
	blockNum := uint64(1)

	header := &types.Header{
		Number:     big.NewInt(int64(blockNum)),
		ParentHash: genesis.Hash(),
		Difficulty: big.NewInt(1),
		GasLimit:   8000000,
		GasUsed:    0,
		Time:       genesis.Time() + 10,
	}
	rawdb.WriteHeader(db, header)
	rawdb.WriteCanonicalHash(db, blockHash, blockNum)
	rawdb.WriteHeaderNumber(db, blockHash, blockNum)

	genBlobs := makeBlkSidecars(1, 1)
	blobHashes := []common.Hash{
		common.HexToHash("0x34ec6e64f9cda8fe0451a391e4798085a3ef51a65ed1bfb016e34fc1a2028f8f"),
	}

	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		Value:      uint256.NewInt(0),
		BlobFeeCap: uint256.NewInt(1),
		BlobHashes: blobHashes,
		Sidecar:    genBlobs[0],
		V:          uint256.NewInt(0),
		R:          uint256.NewInt(0),
		S:          uint256.NewInt(0),
	})

	expectedSidecars := types.BlobSidecars{types.NewBlobSidecarFromTx(tx)}
	rawdb.WriteBlobSidecars(db, blockHash, blockNum, expectedSidecars)

	// First access - populates cache
	sidecars1 := chain.GetSidecarsByHash(blockHash)
	if sidecars1 == nil {
		t.Fatalf("Expected sidecars from DB, got nil")
	}

	// Delete from DB to verify cache is used
	rawdb.DeleteBlobSidecars(db, blockHash, blockNum)

	// Second access - should still work because cache is checked first
	sidecars2 := chain.GetSidecarsByHash(blockHash)
	if sidecars2 == nil {
		t.Fatalf("Expected sidecars from cache after DB deletion, got nil")
	}

	// Verify content matches
	if len(sidecars2) != len(expectedSidecars) {
		t.Fatalf("Cache returned wrong number of sidecars: got %d, want %d", len(sidecars2), len(expectedSidecars))
	}
}

// TestGetSidecarsByHashNonCanonical tests behavior with non-canonical blocks
func TestGetSidecarsByHashNonCanonical(t *testing.T) {
	var (
		db    = rawdb.NewMemoryDatabase()
		gspec = &Genesis{Config: params.TestChainConfig}
	)
	gspec.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))

	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme("hash"), gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	// Create a non-canonical block (no header number mapping)
	blockHash := common.BytesToHash([]byte{0x05, 0x06})

	// Should return nil for non-canonical block
	sidecars := chain.GetSidecarsByHash(blockHash)
	if sidecars != nil {
		t.Fatalf("Expected nil for non-canonical block, got %v", sidecars)
	}
}

// TestGetSidecarsByHashEmptyBlock tests blocks without blob transactions
func TestGetSidecarsByHashEmptyBlock(t *testing.T) {
	var (
		db      = rawdb.NewMemoryDatabase()
		gspec   = &Genesis{Config: params.TestChainConfig}
		genesis = gspec.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))
	)

	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme("hash"), gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	// Create block without blobs
	blockHash := common.BytesToHash([]byte{0x07, 0x08})
	blockNum := uint64(1)

	header := &types.Header{
		Number:     big.NewInt(int64(blockNum)),
		ParentHash: genesis.Hash(),
		Difficulty: big.NewInt(1),
		GasLimit:   8000000,
		GasUsed:    0,
		Time:       genesis.Time() + 10,
	}
	rawdb.WriteHeader(db, header)
	rawdb.WriteCanonicalHash(db, blockHash, blockNum)
	rawdb.WriteHeaderNumber(db, blockHash, blockNum)

	// No blob sidecars written - should return nil
	sidecars := chain.GetSidecarsByHash(blockHash)
	if sidecars != nil {
		t.Fatalf("Expected nil for block without blobs, got %v", sidecars)
	}
}
