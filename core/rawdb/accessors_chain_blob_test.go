package rawdb

import (
	"crypto/rand"
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
// Following BSC pattern: empty sidecars should be stored and retrieved as empty array
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

	// Write nil sidecars - should be stored as empty array (BSC pattern)
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
