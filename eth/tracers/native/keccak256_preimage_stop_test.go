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

package native_test

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/params"
)

// TestKeccak256PreimageTracerStop checks that the keccak256 preimage tracer
// provides a Stop hook. The trace API's timeout watchdog calls tracer.Stop
// unconditionally when the deadline is exceeded, so a nil Stop turns a trace
// timeout into a nil function call.
func TestKeccak256PreimageTracerStop(t *testing.T) {
	tr, err := tracers.DefaultDirectory.New("keccak256PreimageTracer", &tracers.Context{}, nil, params.MainnetChainConfig)
	if err != nil {
		t.Fatalf("failed to create tracer: %v", err)
	}
	if tr.Stop == nil {
		t.Fatal("keccak256PreimageTracer has no Stop hook")
	}
	stopErr := errors.New("execution timeout")
	tr.Stop(stopErr)
	if _, err := tr.GetResult(); !errors.Is(err, stopErr) {
		t.Fatalf("GetResult after Stop: have error %v, want %v", err, stopErr)
	}
}
