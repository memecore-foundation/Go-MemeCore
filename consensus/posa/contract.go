package posa

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

const validatorSetABI = `[ { "inputs": [], "stateMutability": "view", "type": "function", "name": "getValidators", "outputs": [ { "internalType": "address[]", "name": "", "type": "address[]" } ] } ]`
const validatorSetAddr = `0x1234000000000000000000000000000000000002`
const validatorSetMethodGet = `getValidators`

const rewardABI = `[ { "inputs": [ { "internalType": "address", "name": "blockSigner", "type": "address" }, { "internalType": "address[]", "name": "validators", "type": "address[]" } ], "name": "timedTask", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
const rewardAddr = `0x1234000000000000000000000000000000000001`
const rewardMethodSet = `timedTask`

var sysCallAddr = common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")

func (p *PoSA) getCurrentValidators(blockHash common.Hash) ([]common.Address, error) {
	if p.ethAPI == nil {
		return nil, errors.New("eth blockchain API is not initialized, PoSA can't function properly")
	}

	blockNr := rpc.BlockNumberOrHashWithHash(blockHash, false)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel when we are finished consuming integers
	defer cancel()
	data, err := p.validatorSetABI.Pack(validatorSetMethodGet)
	if err != nil {
		log.Error("Unable to pack tx for getValidators", "error", err)
		return nil, err
	}
	// Do smart contract call
	msgData := (hexutil.Bytes)(data)
	toAddress := common.HexToAddress(validatorSetAddr)
	gas := hexutil.Uint64(50_000_000)
	result, err := p.ethAPI.Call(ctx, ethapi.TransactionArgs{
		Gas:  &gas,
		To:   &toAddress,
		Data: &msgData,
	}, &blockNr, nil, nil)
	if err != nil {
		return nil, err
	}

	var valSet []common.Address
	err = p.validatorSetABI.UnpackIntoInterface(&valSet, validatorSetMethodGet, result)
	return valSet, err
}

type chainContext struct {
	chain consensus.ChainHeaderReader
	posa  consensus.Engine
}

func (c chainContext) Engine() consensus.Engine {
	return c.posa
}

func (c chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return c.chain.GetHeader(hash, number)
}

func (p *PoSA) settleRewardsAndUpdateValidators(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, validators map[common.Address]struct{}) {
	// Get the block signer
	signer, err := ecrecover(header, p.signatures)
	// If there is no signature, then the block is preparing
	if err != nil {
		signer = p.signer
	}
	// Get the current validator list
	validatorList := make([]common.Address, 0)
	for validator := range validators {
		validatorList = append(validatorList, validator)
	}
	chainContext := chainContext{
		chain: chain,
		posa:  p,
	}
	context := core.NewEVMBlockContext(header, chainContext, &sysCallAddr)
	vmenv := vm.NewEVM(context, vm.TxContext{}, state, p.chainConfig, p.vmConfig)
	// Check potential overflow
	contractBalance := state.GetBalance(common.HexToAddress(validatorSetAddr))
	blockReward := Phase1BlockReward
	_, overflow := new(uint256.Int).AddOverflow(contractBalance, blockReward)
	if overflow {
		panic("Balance overflow detected")
	}
	// Do smart contract call
	data, err := p.rewardABI.Pack(rewardMethodSet, signer, validatorList)
	if err != nil {
		panic(err)
	}
	toAddress := common.HexToAddress(rewardAddr)
	msg := &core.Message{
		From:      sysCallAddr,
		GasLimit:  50_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &toAddress,
		Data:      data,
	}
	vmenv.Reset(core.NewEVMTxContext(msg), state)
	state.AddAddressToAccessList(toAddress)
	_, _, err = vmenv.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 50_000_000, common.U2560)
	if err != nil {
		panic(err)
	}
	state.Finalise(true)
}
