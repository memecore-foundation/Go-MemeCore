package rawdb

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/rlp"
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

// checkBlobSidecarsRLP verifies that two BlobSidecars have identical RLP encoding
func checkBlobSidecarsRLP(have, want types.BlobSidecars) error {
	if len(have) != len(want) {
		return fmt.Errorf("blob sidecars count mismatch: have %d, want %d", len(have), len(want))
	}
	for i := 0; i < len(want); i++ {
		rlpHave, err := rlp.EncodeToBytes(have[i])
		if err != nil {
			return fmt.Errorf("failed to encode have[%d]: %v", i, err)
		}
		rlpWant, err := rlp.EncodeToBytes(want[i])
		if err != nil {
			return fmt.Errorf("failed to encode want[%d]: %v", i, err)
		}
		if !bytes.Equal(rlpHave, rlpWant) {
			return fmt.Errorf("blob sidecar #%d RLP mismatch", i)
		}
	}
	return nil
}

// TestBlobSidecarsReadWrite tests basic read/write/delete operations
func TestBlobSidecarsReadWrite(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x01, 0x02})
	blockNum := uint64(1)

	// Create test blob sidecars
	genBlobs := makeBlkSidecars(1, 2)
	blobHashes := []common.Hash{
		common.HexToHash("0x34ec6e64f9cda8fe0451a391e4798085a3ef51a65ed1bfb016e34fc1a2028f8f"),
		common.HexToHash("0xb9a412e875f29fac436acde234f954e91173c4cf79814f6dcf630d8a6345747f"),
	}

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

	sidecars := types.BlobSidecars{types.NewBlobSidecarFromTx(tx1)}

	// Test 1: Non-existent sidecars should return nil
	if bs := ReadBlobSidecars(db, blockHash, blockNum); bs != nil {
		t.Fatalf("Expected nil for non-existent sidecars, got %v", bs)
	}

	// Test 2: Write sidecars
	WriteBlobSidecars(db, blockHash, blockNum, sidecars)

	// Test 3: Read sidecars back
	retrieved := ReadBlobSidecars(db, blockHash, blockNum)
	if retrieved == nil {
		t.Fatalf("Expected sidecars after write, got nil")
	}
	if len(retrieved) != len(sidecars) {
		t.Fatalf("Sidecar count mismatch: got %d, want %d", len(retrieved), len(sidecars))
	}

	// Test 4: Verify RLP encoding matches
	originalRLP, err := rlp.EncodeToBytes(sidecars)
	if err != nil {
		t.Fatalf("Failed to encode original sidecars: %v", err)
	}
	retrievedRLP, err := rlp.EncodeToBytes(retrieved)
	if err != nil {
		t.Fatalf("Failed to encode retrieved sidecars: %v", err)
	}
	if string(originalRLP) != string(retrievedRLP) {
		t.Fatalf("RLP mismatch:\noriginal:  %x\nretrieved: %x", originalRLP, retrievedRLP)
	}

	// Test 5: Delete sidecars
	DeleteBlobSidecars(db, blockHash, blockNum)
	if bs := ReadBlobSidecars(db, blockHash, blockNum); bs != nil {
		t.Fatalf("Expected nil after deletion, got %v", bs)
	}
}

// TestBlobSidecarsMultipleBlocks tests handling multiple blocks
func TestBlobSidecarsMultipleBlocks(t *testing.T) {
	db := NewMemoryDatabase()

	// Create sidecars for multiple blocks
	blocks := []struct {
		hash common.Hash
		num  uint64
		blobs int
	}{
		{common.BytesToHash([]byte{0x01}), 1, 1},
		{common.BytesToHash([]byte{0x02}), 2, 2},
		{common.BytesToHash([]byte{0x03}), 3, 3},
	}

	// Write sidecars for each block
	for _, block := range blocks {
		genBlobs := makeBlkSidecars(block.blobs, 1)
		var sidecars types.BlobSidecars
		for _, blob := range genBlobs {
			sidecars = append(sidecars, &types.BlobSidecar{BlobTxSidecar: *blob})
		}
		WriteBlobSidecars(db, block.hash, block.num, sidecars)
	}

	// Verify each block's sidecars
	for _, block := range blocks {
		retrieved := ReadBlobSidecars(db, block.hash, block.num)
		if retrieved == nil {
			t.Fatalf("Block %d: Expected sidecars, got nil", block.num)
		}
		if len(retrieved) != block.blobs {
			t.Fatalf("Block %d: Expected %d sidecars, got %d", block.num, block.blobs, len(retrieved))
		}
	}
}

// TestBlobSidecarsRLP tests RLP encoding/decoding
func TestBlobSidecarsRLP(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x04})
	blockNum := uint64(4)

	// Create test sidecars
	genBlobs := makeBlkSidecars(2, 1)
	var sidecars types.BlobSidecars
	for _, blob := range genBlobs {
		sidecars = append(sidecars, &types.BlobSidecar{BlobTxSidecar: *blob})
	}

	// Write using WriteBlobSidecars
	WriteBlobSidecars(db, blockHash, blockNum, sidecars)

	// Read using ReadBlobSidecarsRLP
	rlpData := ReadBlobSidecarsRLP(db, blockHash, blockNum)
	if len(rlpData) == 0 {
		t.Fatalf("Expected RLP data, got empty")
	}

	// Decode and verify
	var decoded types.BlobSidecars
	if err := rlp.DecodeBytes(rlpData, &decoded); err != nil {
		t.Fatalf("Failed to decode RLP: %v", err)
	}

	if len(decoded) != len(sidecars) {
		t.Fatalf("Decoded count mismatch: got %d, want %d", len(decoded), len(sidecars))
	}
}

// TestBlobSidecarsEmptySidecars tests handling of empty sidecars
// Empty sidecars should be stored and retrieved as empty array
func TestBlobSidecarsEmptySidecars(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x05})
	blockNum := uint64(5)

	// Write empty sidecars (zero-length array)
	emptySidecars := types.BlobSidecars{}
	WriteBlobSidecars(db, blockHash, blockNum, emptySidecars)

	// Read back - should get empty array, not nil
	// This distinguishes "no blob transactions" from "data not available"
	retrieved := ReadBlobSidecars(db, blockHash, blockNum)
	if retrieved == nil {
		t.Fatalf("Expected empty array, got nil")
	}
	if len(retrieved) != 0 {
		t.Fatalf("Expected empty array, got %d sidecars", len(retrieved))
	}
}

// TestBlobSidecarsNilHandling tests that nil sidecars are stored as empty array
func TestBlobSidecarsNilHandling(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x06})
	blockNum := uint64(6)

	// Write nil sidecars - should be stored as empty array
	WriteBlobSidecars(db, blockHash, blockNum, nil)

	// Read back - RLP encoding of nil should decode to empty array
	retrieved := ReadBlobSidecars(db, blockHash, blockNum)
	if retrieved == nil {
		t.Fatalf("Expected empty array for nil input, got nil")
	}
	if len(retrieved) != 0 {
		t.Fatalf("Expected empty array for nil input, got %d sidecars", len(retrieved))
	}
}

// TestDeleteBlockWithBlobSidecars tests that DeleteBlock prevents blob sidecar leak
func TestDeleteBlockWithBlobSidecars(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x07})
	blockNum := uint64(7)

	// Create test blob sidecar
	genBlobs := makeBlkSidecars(1, 1)
	blobHash := common.HexToHash("0x34ec6e64f9cda8fe0451a391e4798085a3ef51a65ed1bfb016e34fc1a2028f8f")

	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		Value:      uint256.NewInt(0),
		Data:       nil,
		BlobFeeCap: uint256.NewInt(1),
		BlobHashes: []common.Hash{blobHash},
		Sidecar:    genBlobs[0],
		V:          uint256.NewInt(0),
		R:          uint256.NewInt(0),
		S:          uint256.NewInt(0),
	})

	sidecars := types.BlobSidecars{types.NewBlobSidecarFromTx(tx)}

	// Write blob sidecars
	WriteBlobSidecars(db, blockHash, blockNum, sidecars)

	// Verify sidecars exist and RLP matches
	retrieved := ReadBlobSidecars(db, blockHash, blockNum)
	if retrieved == nil {
		t.Fatalf("Expected sidecars after write, got nil")
	}
	if err := checkBlobSidecarsRLP(retrieved, sidecars); err != nil {
		t.Fatalf("RLP verification failed: %v", err)
	}

	// Delete block (which should delete blob sidecars too)
	DeleteBlock(db, blockHash, blockNum)

	// Verify blob sidecars are deleted
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil after DeleteBlock, but blob sidecars still exist")
	}
}

// TestDeleteBlockWithoutNumberWithBlobSidecars tests that DeleteBlockWithoutNumber prevents blob sidecar leak
func TestDeleteBlockWithoutNumberWithBlobSidecars(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x08})
	blockNum := uint64(8)

	// Create test blob sidecar
	genBlobs := makeBlkSidecars(1, 1)
	blobHash := common.HexToHash("0xb9a412e875f29fac436acde234f954e91173c4cf79814f6dcf630d8a6345747f")

	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		Value:      uint256.NewInt(0),
		Data:       nil,
		BlobFeeCap: uint256.NewInt(1),
		BlobHashes: []common.Hash{blobHash},
		Sidecar:    genBlobs[0],
		V:          uint256.NewInt(0),
		R:          uint256.NewInt(0),
		S:          uint256.NewInt(0),
	})

	sidecars := types.BlobSidecars{types.NewBlobSidecarFromTx(tx)}

	// Write blob sidecars
	WriteBlobSidecars(db, blockHash, blockNum, sidecars)

	// Verify sidecars exist and RLP matches
	retrieved := ReadBlobSidecars(db, blockHash, blockNum)
	if retrieved == nil {
		t.Fatalf("Expected sidecars after write, got nil")
	}
	if err := checkBlobSidecarsRLP(retrieved, sidecars); err != nil {
		t.Fatalf("RLP verification failed: %v", err)
	}

	// Delete block without number (which should delete blob sidecars too)
	DeleteBlockWithoutNumber(db, blockHash, blockNum)

	// Verify blob sidecars are deleted
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil after DeleteBlockWithoutNumber, but blob sidecars still exist")
	}
}

// TestDeleteBlockPreCancun tests that DeleteBlock is safe for pre-Cancun blocks (no blob sidecars)
func TestDeleteBlockPreCancun(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x09})
	blockNum := uint64(9)

	// Verify no sidecars exist
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil for non-existent sidecars, got %v", retrieved)
	}

	// Delete block (should not panic or error even though blob sidecars don't exist)
	DeleteBlock(db, blockHash, blockNum)

	// Should still be nil
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil after delete, got %v", retrieved)
	}
}

// TestDeleteBlockWithMultipleBlobsPerTx tests DeleteBlock with maximum blobs per transaction (6)
func TestDeleteBlockWithMultipleBlobsPerTx(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x10})
	blockNum := uint64(10)

	// Create 6 blobs (maximum per transaction according to EIP-4844)
	genBlobs := makeBlkSidecars(1, 6)
	blobHashes := []common.Hash{
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000003"),
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004"),
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005"),
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000006"),
	}

	tx := types.NewTx(&types.BlobTx{
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

	sidecars := types.BlobSidecars{types.NewBlobSidecarFromTx(tx)}

	// Write blob sidecars
	WriteBlobSidecars(db, blockHash, blockNum, sidecars)

	// Verify 6 blobs written correctly
	retrieved := ReadBlobSidecars(db, blockHash, blockNum)
	if retrieved == nil {
		t.Fatalf("Expected sidecars with 6 blobs, got nil")
	}
	if len(retrieved) != 1 {
		t.Fatalf("Expected 1 sidecar, got %d", len(retrieved))
	}
	if len(retrieved[0].Blobs) != 6 {
		t.Fatalf("Expected 6 blobs in sidecar, got %d", len(retrieved[0].Blobs))
	}
	if err := checkBlobSidecarsRLP(retrieved, sidecars); err != nil {
		t.Fatalf("RLP verification failed: %v", err)
	}

	// Delete block
	DeleteBlock(db, blockHash, blockNum)

	// Verify all 6 blobs deleted
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil after DeleteBlock, but sidecars with %d blobs still exist", len(retrieved[0].Blobs))
	}
}

// TestDeleteBlockWithMultipleBlobTxs tests DeleteBlock with multiple blob transactions in one block
// Real blocks can contain multiple blob transactions
func TestDeleteBlockWithMultipleBlobTxs(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x11})
	blockNum := uint64(11)

	// Create 3 blob transactions with different blob counts (2, 3, 1)
	genBlobs1 := makeBlkSidecars(1, 2)
	genBlobs2 := makeBlkSidecars(1, 3)
	genBlobs3 := makeBlkSidecars(1, 1)

	tx1 := types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		BlobHashes: []common.Hash{
			common.HexToHash("0x1000000000000000000000000000000000000000000000000000000000000001"),
			common.HexToHash("0x1000000000000000000000000000000000000000000000000000000000000002"),
		},
		Sidecar: genBlobs1[0],
	})

	tx2 := types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		BlobHashes: []common.Hash{
			common.HexToHash("0x2000000000000000000000000000000000000000000000000000000000000001"),
			common.HexToHash("0x2000000000000000000000000000000000000000000000000000000000000002"),
			common.HexToHash("0x2000000000000000000000000000000000000000000000000000000000000003"),
		},
		Sidecar: genBlobs2[0],
	})

	tx3 := types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		Gas:        21000,
		BlobHashes: []common.Hash{
			common.HexToHash("0x3000000000000000000000000000000000000000000000000000000000000001"),
		},
		Sidecar: genBlobs3[0],
	})

	sidecars := types.BlobSidecars{
		types.NewBlobSidecarFromTx(tx1),
		types.NewBlobSidecarFromTx(tx2),
		types.NewBlobSidecarFromTx(tx3),
	}

	// Write blob sidecars
	WriteBlobSidecars(db, blockHash, blockNum, sidecars)

	// Verify 3 sidecar entries (total 6 blobs: 2+3+1)
	retrieved := ReadBlobSidecars(db, blockHash, blockNum)
	if retrieved == nil {
		t.Fatalf("Expected 3 blob sidecars, got nil")
	}
	if len(retrieved) != 3 {
		t.Fatalf("Expected 3 sidecars, got %d", len(retrieved))
	}
	if len(retrieved[0].Blobs) != 2 {
		t.Fatalf("Expected 2 blobs in first sidecar, got %d", len(retrieved[0].Blobs))
	}
	if len(retrieved[1].Blobs) != 3 {
		t.Fatalf("Expected 3 blobs in second sidecar, got %d", len(retrieved[1].Blobs))
	}
	if len(retrieved[2].Blobs) != 1 {
		t.Fatalf("Expected 1 blob in third sidecar, got %d", len(retrieved[2].Blobs))
	}
	if err := checkBlobSidecarsRLP(retrieved, sidecars); err != nil {
		t.Fatalf("RLP verification failed: %v", err)
	}

	// Delete block
	DeleteBlock(db, blockHash, blockNum)

	// Verify all sidecars deleted
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil after DeleteBlock, but %d sidecars still exist", len(retrieved))
	}
}

// TestBatchDeleteBlocksWithBlobs tests that batch deletion prevents blob sidecar leaks
// This simulates the freezer's side chain cleanup pattern
func TestBatchDeleteBlocksWithBlobs(t *testing.T) {
	db := NewMemoryDatabase()
	batch := db.NewBatch()

	// Create 10 blocks with blob sidecars
	type blockInfo struct {
		hash     common.Hash
		num      uint64
		sidecars types.BlobSidecars
	}
	blocks := make([]blockInfo, 10)

	for i := 0; i < 10; i++ {
		blocks[i].hash = common.BytesToHash([]byte{byte(0x20 + i)})
		blocks[i].num = uint64(100 + i)

		// Create 2 blobs per block
		genBlobs := makeBlkSidecars(1, 2)
		tx := types.NewTx(&types.BlobTx{
			ChainID:    uint256.NewInt(1),
			GasTipCap:  uint256.NewInt(1),
			GasFeeCap:  uint256.NewInt(1),
			Gas:        21000,
			BlobHashes: []common.Hash{
				common.BytesToHash([]byte{byte(i), 0x01}),
				common.BytesToHash([]byte{byte(i), 0x02}),
			},
			Sidecar: genBlobs[0],
		})
		blocks[i].sidecars = types.BlobSidecars{types.NewBlobSidecarFromTx(tx)}

		// Write sidecars
		WriteBlobSidecars(db, blocks[i].hash, blocks[i].num, blocks[i].sidecars)
	}

	// Verify all 10 blocks have sidecars
	for i := 0; i < 10; i++ {
		retrieved := ReadBlobSidecars(db, blocks[i].hash, blocks[i].num)
		if retrieved == nil {
			t.Fatalf("Block %d: Expected sidecars, got nil", i)
		}
		if err := checkBlobSidecarsRLP(retrieved, blocks[i].sidecars); err != nil {
			t.Fatalf("Block %d: RLP verification failed: %v", i, err)
		}
	}

	// Batch delete all 10 blocks (simulating freezer side chain cleanup)
	batch = db.NewBatch()
	for i := 0; i < 10; i++ {
		DeleteBlock(batch, blocks[i].hash, blocks[i].num)
	}
	if err := batch.Write(); err != nil {
		t.Fatalf("Batch write failed: %v", err)
	}

	// Verify all 10 blocks' sidecars are deleted
	for i := 0; i < 10; i++ {
		if retrieved := ReadBlobSidecars(db, blocks[i].hash, blocks[i].num); retrieved != nil {
			t.Fatalf("Block %d: Expected nil after batch delete, but sidecars still exist", i)
		}
	}
}

// TestDeleteBlockWithoutNumberPreCancun tests DeleteBlockWithoutNumber safety for pre-Cancun blocks
func TestDeleteBlockWithoutNumberPreCancun(t *testing.T) {
	db := NewMemoryDatabase()
	blockHash := common.BytesToHash([]byte{0x30})
	blockNum := uint64(30)

	// Verify no sidecars exist
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil for non-existent sidecars, got %v", retrieved)
	}

	// Delete block without number (should not panic or error)
	DeleteBlockWithoutNumber(db, blockHash, blockNum)

	// Should still be nil
	if retrieved := ReadBlobSidecars(db, blockHash, blockNum); retrieved != nil {
		t.Fatalf("Expected nil after delete, got %v", retrieved)
	}
}
