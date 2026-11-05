// Copyright 2026 The go-ethereum Authors
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

package tracers_test

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// TestTraceBlockByNumberKeccakTimeout traces a block with the keccak256 preimage
// tracer and a deadline that has already passed. traceTx then runs its timeout
// watchdog, which calls tracer.Stop from its own goroutine; a tracer without a
// Stop hook makes that goroutine call a nil function, which terminates the process.
func TestTraceBlockByNumberKeccakTimeout(t *testing.T) {
	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc:  types.GenesisAlloc{from: {Balance: big.NewInt(params.Ether)}},
	}
	signer := types.HomesteadSigner{}
	backend := tracers.NewTestBackend(t, 1, genesis, func(i int, b *core.BlockGen) {
		tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    uint64(i),
			To:       &to,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: b.BaseFee(),
		}), signer, key)
		b.AddTx(tx)
	})
	defer tracers.TeardownTestBackend(backend)

	api := tracers.NewAPI(backend)
	name, timeout := "keccak256PreimageTracer", "1ns"
	res, err := api.TraceBlockByNumber(context.Background(), rpc.BlockNumber(1), &tracers.TraceConfig{Tracer: &name, Timeout: &timeout})
	switch {
	case err != nil:
		// The watchdog may stop the tracer before the transaction finishes. The
		// timeout is then reported as an error, which is also a correct outcome.
		if !strings.Contains(err.Error(), "execution timeout") {
			t.Fatalf("TraceBlockByNumber failed: %v", err)
		}
	case len(res) != 1:
		t.Fatalf("got %d transaction results, want 1", len(res))
	}
	// The watchdog fires asynchronously, possibly after the result is returned.
	time.Sleep(500 * time.Millisecond)
}
