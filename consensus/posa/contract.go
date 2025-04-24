package posa

import (
	"context"
	"errors"
	"fmt"

	"encoding/hex"

	"github.com/ethereum/go-ethereum/accounts/abi"

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
		log.Error("Unable to get validators", "error", err)
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

func (p *PoSA) settleRewardsAndUpdateValidators(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, validators map[common.Address]struct{}) error {
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

        // Check if the RewardTreeFork is active for this block
        if chain.Config().IsRewardTreeFork(header.Number) == true {
                blockReward = RewardTreeForkBlockReward
        }

	_, overflow := new(uint256.Int).AddOverflow(contractBalance, blockReward)
	if overflow {
		log.Error("Balance overflow detected")
		return errors.New("validator contract balance overflow")
	}
	// Do smart contract call
	data, err := p.rewardABI.Pack(rewardMethodSet, signer, validatorList)
	if err != nil {
		log.Error("Unable to pack tx for timedTask", "error", err)
		return err
	}

	toAddress := common.HexToAddress(rewardAddr)
	msg := &core.Message{
		From:      sysCallAddr,
		GasLimit:  uint64(50_000_000),
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &toAddress,
		Data:      data,
	}
	vmenv.Reset(core.NewEVMTxContext(msg), state)
	state.AddAddressToAccessList(toAddress)
	ret, leftOverGas, err := vmenv.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, msg.GasLimit, common.U2560)
	// Log execution result and events if enabled
	if p.enableEventLogging {
		if err != nil {
			revertMsg, unpackErr := abi.UnpackRevert(ret)
			if unpackErr == nil {
				log.Error("Contract execution failed", "error", err, "revert_reason", revertMsg, "gas_used", msg.GasLimit-leftOverGas)
			} else {
				log.Error("Contract execution failed", "error", err, "hex_data", hexutil.Encode(ret), "gas_used", msg.GasLimit-leftOverGas)
			}
		} else {
			if len(ret) > 0 {
				log.Info("Contract executed", "gas_used", msg.GasLimit-leftOverGas, "return_data", hexutil.Encode(ret))
			} else {
				log.Info("Contract executed", "gas_used", msg.GasLimit-leftOverGas)
			}
		}
		// Process emitted logs
		logs := state.Logs()
		if len(logs) > 0 {
			log.Info("Transaction Logs", "tx_hash", logs[0].TxHash.String())
			for i, evmLog := range logs {
				log.Info(fmt.Sprintf("Log Entry[%d] Address=%s", i, evmLog.Address.String()))
				for j, topic := range evmLog.Topics {
					log.Info(fmt.Sprintf("Topic[%d] hex=%s", j, topic.Hex()))
				}
				if len(evmLog.Data) > 0 {
					log.Info(fmt.Sprintf("Data hex=%s", "0x"+hex.EncodeToString(evmLog.Data)))
				}
				if i < len(logs)-1 {
					log.Info("----------------------------------------")
				}
			}
		}
	}

	state.Finalise(true)
	return nil
}
