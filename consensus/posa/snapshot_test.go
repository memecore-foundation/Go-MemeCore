package posa

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// testerAccountPool is a pool to maintain currently active tester accounts,
// mapped from textual names used in the tests below to actual Ethereum private
// keys capable of signing transactions.
type testerAccountPool struct {
	accounts map[string]*ecdsa.PrivateKey
}

func newTesterAccountPool() *testerAccountPool {
	return &testerAccountPool{
		accounts: make(map[string]*ecdsa.PrivateKey),
	}
}

// checkpoint creates a PoSA checkpoint signer section from the provided list
// of authorized signers and embeds it into the provided header.
func (ap *testerAccountPool) checkpoint(header *types.Header, signers []string) {
	auths := make([]common.Address, len(signers))
	for i, signer := range signers {
		auths[i] = ap.address(signer)
	}
	slices.SortFunc(auths, common.Address.Cmp)
	for i, auth := range auths {
		copy(header.Extra[extraVanity+i*common.AddressLength:], auth.Bytes())
	}
}

// address retrieves the Ethereum address of a tester account by label, creating
// a new account if no previous one exists yet.
func (ap *testerAccountPool) address(account string) common.Address {
	// Return the zero account for non-addresses
	if account == "" {
		return common.Address{}
	}
	// Ensure we have a persistent key for the account
	if ap.accounts[account] == nil {
		ap.accounts[account], _ = crypto.GenerateKey()
	}
	// Resolve and return the Ethereum address
	return crypto.PubkeyToAddress(ap.accounts[account].PublicKey)
}

// sign calculates a PoSA digital signature for the given block and embeds it
// back into the header.
func (ap *testerAccountPool) sign(header *types.Header, signer string) {
	// Ensure we have a persistent key for the signer
	if ap.accounts[signer] == nil {
		ap.accounts[signer], _ = crypto.GenerateKey()
	}
	// Sign the header and embed the signature in extra data
	sig, _ := crypto.Sign(SealHash(header).Bytes(), ap.accounts[signer])
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)
}

type testerSnap struct {
	signer     string
	checkpoint []string
	newbatch   bool
}

type posaTest struct {
	epoch   uint64
	signers []string
	snaps   []testerSnap
	results []string
	failure error
}

// Tests that PoSA signer voting is evaluated correctly for various simple and
// complex scenarios, as well as that a few special corner cases fail correctly.
func TestPoSA(t *testing.T) {
	// Define the various voting scenarios to test
	tests := []posaTest{
		{
			// Single signer
			signers: []string{"A"},
			snaps: []testerSnap{
				{signer: "A"},
			},
			results: []string{"A"},
		}, {
			// Two signers
			signers: []string{"A", "B"},
			snaps: []testerSnap{
				{signer: "A"},
				{signer: "B"},
			},
			results: []string{"A", "B"},
		}, {
			// Three signers
			signers: []string{"A", "B", "C"},
			snaps: []testerSnap{
				{signer: "C"},
				{signer: "A"},
				{signer: "B"},
			},
			results: []string{"A", "B", "C"},
		}, {
			// Four signers
			signers: []string{"A", "B", "C", "D"},
			snaps: []testerSnap{
				{signer: "A"},
				{signer: "B"},
				{signer: "C"},
				{signer: "A"},
				{signer: "B"},
				{signer: "C"},
				{signer: "A"},
				{signer: "B"},
				{signer: "C"},
			},
			results: []string{"A", "B", "C", "D"},
		}, {
			// Five signers
			signers: []string{"A", "B", "C", "D", "E"},
			snaps: []testerSnap{
				{signer: "A"},
				{signer: "B"},
				{signer: "C"},
				{signer: "D"},
				{signer: "E"},
				{signer: "B"},
				{signer: "C"},
				{signer: "D"},
				{signer: "E"},
				{signer: "B"},
				{signer: "C"},
				{signer: "D"},
				{signer: "B"},
			},
			results: []string{"A", "B", "C", "D", "E"},
		}, {
			// Epoch transitions
			epoch:   3,
			signers: []string{"A", "B"},
			snaps: []testerSnap{
				{signer: "A"},
				{signer: "B"},
				{signer: "A", checkpoint: []string{"A", "B"}},
				{signer: "B"},
			},
			results: []string{"A", "B"},
		}, {
			// An unauthorized signer should not be able to sign blocks
			signers: []string{"A"},
			snaps: []testerSnap{
				{signer: "B"},
			},
			failure: errUnauthorizedSigner,
		}, {
			// An authorized signer that signed recently should not be able to sign again
			signers: []string{"A", "B"},
			snaps: []testerSnap{
				{signer: "A"},
				{signer: "A"},
			},
			failure: errRecentlySigned,
		}, {
			// Recent signatures should not reset on checkpoint blocks imported in a batch
			epoch:   3,
			signers: []string{"A", "B", "C"},
			snaps: []testerSnap{
				{signer: "A"},
				{signer: "B"},
				{signer: "A", checkpoint: []string{"A", "B", "C"}},
				{signer: "A"},
			},
			failure: errRecentlySigned,
		}, {
			// Recent signatures should not reset on checkpoint blocks imported in a new
			// batch (https://github.com/ethereum/go-ethereum/issues/17593). Whilst this
			// seems overly specific and weird, it was a Rinkeby consensus split.
			epoch:   3,
			signers: []string{"A", "B", "C"},
			snaps: []testerSnap{
				{signer: "A"},
				{signer: "B"},
				{signer: "A", checkpoint: []string{"A", "B", "C"}},
				{signer: "A", newbatch: true},
			},
			failure: errRecentlySigned,
		},
	}

	// Run through the scenarios and test them
	for i, tt := range tests {
		t.Run(fmt.Sprint(i), tt.run)
	}
}

func (tt *posaTest) run(t *testing.T) {
	// Create the account pool and generate the initial set of signers
	accounts := newTesterAccountPool()

	signers := make([]common.Address, len(tt.signers))
	for j, signer := range tt.signers {
		signers[j] = accounts.address(signer)
	}
	for j := 0; j < len(signers); j++ {
		for k := j + 1; k < len(signers); k++ {
			if bytes.Compare(signers[j][:], signers[k][:]) > 0 {
				signers[j], signers[k] = signers[k], signers[j]
			}
		}
	}
	// Create the genesis block with the initial set of signers
	genesis := &core.Genesis{
		ExtraData: make([]byte, extraVanity+common.AddressLength*len(signers)+extraSeal),
		BaseFee:   big.NewInt(params.InitialBaseFee),
	}
	for j, signer := range signers {
		copy(genesis.ExtraData[extraVanity+j*common.AddressLength:], signer[:])
	}

	// Assemble a chain of headers from the cast votes
	config := *params.TestChainConfig
	config.PoSA = &params.PoSAConfig{
		Period: 1,
		Epoch:  tt.epoch,
	}
	genesis.Config = &config

	engine := New(config.PoSA, rawdb.NewMemoryDatabase())
	engine.fakeDiff = true

	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, len(tt.snaps), func(j int, gen *core.BlockGen) {
		// Cast the vote contained in this block
		gen.SetCoinbase(accounts.address(tt.snaps[j].signer))
		if tt.epoch == 0 || (j+1)%int(tt.epoch) != 0 {
			var nonce types.BlockNonce
			copy(nonce[:], nonceAuthVote)
			gen.SetNonce(nonce)
		}
	})
	// Iterate through the blocks and seal them individually
	for j, block := range blocks {
		// Get the header and prepare it for signing
		header := block.Header()
		if j > 0 {
			header.ParentHash = blocks[j-1].Hash()
		}
		header.Extra = make([]byte, extraVanity+extraSeal)
		if auths := tt.snaps[j].checkpoint; auths != nil {
			header.Extra = make([]byte, extraVanity+len(auths)*common.AddressLength+extraSeal)
			accounts.checkpoint(header, auths)
		}
		header.Difficulty = diffInTurn // Ignored, we just need a valid number

		// Generate the signature, embed it into the header and the block
		accounts.sign(header, tt.snaps[j].signer)
		blocks[j] = block.WithSeal(header)
	}
	// Split the blocks up into individual import batches (cornercase testing)
	batches := [][]*types.Block{nil}
	for j, block := range blocks {
		if tt.snaps[j].newbatch {
			batches = append(batches, nil)
		}
		batches[len(batches)-1] = append(batches[len(batches)-1], block)
	}
	// Pass all the headers through posa
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("failed to create test chain: %v", err)
	}
	defer chain.Stop()

	for j := 0; j < len(batches)-1; j++ {
		if k, err := chain.InsertChain(batches[j]); err != nil {
			t.Fatalf("failed to import batch %d, block %d: %v", j, k, err)
		}
	}
	if _, err = chain.InsertChain(batches[len(batches)-1]); err != tt.failure {
		t.Errorf("failure mismatch: have %v, want %v", err, tt.failure)
	}
	if tt.failure != nil {
		return
	}

	// No failure was produced or requested, generate the final voting snapshot
	head := blocks[len(blocks)-1]

	snap, err := engine.snapshot(chain, head.NumberU64(), head.Hash(), nil)
	if err != nil {
		t.Fatalf("failed to retrieve voting snapshot: %v", err)
	}
	// Verify the final list of signers against the expected ones
	signers = make([]common.Address, len(tt.results))
	for j, signer := range tt.results {
		signers[j] = accounts.address(signer)
	}
	for j := 0; j < len(signers); j++ {
		for k := j + 1; k < len(signers); k++ {
			if bytes.Compare(signers[j][:], signers[k][:]) > 0 {
				signers[j], signers[k] = signers[k], signers[j]
			}
		}
	}
	result := snap.signers()
	if len(result) != len(signers) {
		t.Fatalf("signers mismatch: have %x, want %x", result, signers)
	}
	for j := 0; j < len(result); j++ {
		if !bytes.Equal(result[j][:], signers[j][:]) {
			t.Fatalf("signer %d: signer mismatch: have %x, want %x", j, result[j], signers[j])
		}
	}
}
