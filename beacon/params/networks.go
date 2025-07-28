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

package params

import (
	_ "embed"

	"github.com/ethereum/go-ethereum/common"
)

//go:embed checkpoint_mainnet.hex
var checkpointMainnet string

//go:embed checkpoint_sepolia.hex
var checkpointSepolia string

//go:embed checkpoint_holesky.hex
var checkpointHolesky string

var (
	MainnetLightConfig = (&ChainConfig{
		GenesisValidatorsRoot: common.HexToHash("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
		GenesisTime:           1606824023,
		Checkpoint:            common.HexToHash(checkpointMainnet),
	}).
		AddFork("GENESIS", 0, []byte{0, 0, 0, 0}).
		AddFork("ALTAIR", 74240, []byte{1, 0, 0, 0}).
		AddFork("BELLATRIX", 144896, []byte{2, 0, 0, 0}).
		AddFork("CAPELLA", 194048, []byte{3, 0, 0, 0}).
		AddFork("DENEB", 269568, []byte{4, 0, 0, 0}).
		AddFork("ELECTRA", 364032, []byte{5, 0, 0, 0})
)
