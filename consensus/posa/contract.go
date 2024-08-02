package posa

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

const validatorSetABI = `[ { "inputs": [], "name": "getCurrentValidators", "outputs": [ { "internalType": "address[]", "name": "", "type": "address[]" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "name": "validators", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" } ]`
const validatorSetAddr = `0x1234000000000000000000000000000000000001`
const validatorSetMethodGet = `getCurrentValidators`

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
