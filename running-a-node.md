# Running a Node

This document contains step-by-step instructions for running a gmeme node in MemeCore network.

## Hardware Requirements

The following are the minimum hardware requirements:

* CPU with 2+ cores
* 4GB RAM
* 200GB free storage space
* 8 MBit/sec download Internet service

## 1. Building or Downloading Gmeme Binary

### Build the source

Building `gmeme` requires both a Go (version 1.19 or later) and a C compiler. Feel free to install them with the package manager of your choice.

Once the dependencies are installed, run

```
make gmeme
```

or, build the full suite of utilities:

```
make all
```

## 2. Initializing Node Account

You can create a new account or import an existing account for your node operation. Seed nodes don't need node account.

### Create a new account

Create your node account with the following command. A password is required to be entered during the process. The resulting account is placed in the specified `--datadir` under the `keystore` path, here we use `./node` as the data directory.

```
./gmeme --datadir ./node account new
```

### Import your existing account

Import your existing account with the private key and remember to replace the `./your/privateKey.txt` parameter.

```
./gmeme account import --datadir ./node ./your/privateKey.txt
```

## 3. Running Seed Node

A seed node is a network member that does not participate in the consensus process. This node can be used to interact with the MimNetwork, including: creating accounts, transferring funds, deploying and interacting with contracts, and querying node APIs.

Create the `startSeed.sh` file in the same folder of `gmeme`. You may need to change the `P2P/HTTP/RPC/WS` ports to avoid conflicts. Please note that the port configuration for the JSON-RPC interface should be set to httpport, not rpcport. Additionally, remember to change `extip` to your own IP address if you want other nodes to be able to find yours. You can refer to [https://geth.ethereum.org/docs/fundamentals/command-line-options](https://geth.ethereum.org/docs/fundamentals/command-line-options) for more details about start options.

This script expects node DB directory to be `./node`.

#### Testnet:

```
#!/bin/bash

node="node"

port=30301
httpport=8551
rpcport=8561
wsport=8571
extip=127.0.0.1

echo "$node and miner is $miner, rpc port $rpcport, p2p port $port"

nohup ./gmeme \
--formicarium \
--nat extip:$extip \
--port $port \
--authrpc.port $rpcport \
--identity=$node \
--maxpeers=50 \
--syncmode full \
--gcmode archive \
--datadir $node \
--http.api admin,eth,debug,miner,net,txpool,personal,web3 \
--http --http.addr 0.0.0.0 --http.port $httpport --http.vhosts "*" --http.corsdomain '*' \
--ws --ws.addr 0.0.0.0 --ws.port $wsport --ws.api eth,net,web3 --ws.origins '*'  \
--verbosity 3  >> $node/node.log 2>&1 &

sleep 3s;
ps -ef|grep gmeme|grep mine|grep -v grep;
```

## 4. Running Miner Node

A miner node participates in the PoSA consensus. If you want to register as a candidate for PoSA validators, you need to run a miner node.

Create the `startMiner.sh` file in the same folder of `gmeme`. You may need to change the `P2P/RPC` ports to avoid conflicts. Additionally, remember to change `extip` if you want other nodes to be able to find yours. You can refer to [https://geth.ethereum.org/docs/fundamentals/command-line-options](https://geth.ethereum.org/docs/fundamentals/command-line-options) for more details about start options.

When the inputing node index is set to 1, this script requires the node address to be placed at `node/node_address.txt`, the node password to be placed at `node/password.txt` and the node DB directory to be placed at `./node`.

#### Testnet:

```
#!/bin/bash

node="node"

port=30301
rpcport=8561
extip=127.0.0.1

miner=$(<$node/node_address.txt)
echo "$node and miner is $miner, rpc port $rpcport, p2p port $port"

nohup ./gmeme \
--formicarium \
--nat extip:$extip \
--port $port \
--mine --miner.etherbase=$miner \
--unlock $miner \
--password $node/password.txt \
--authrpc.port $rpcport \
--identity=$node \
--maxpeers=50 \
--syncmode full \
--gcmode archive \
--datadir $node \
--verbosity 3  >> $node/node.log 2>&1 &

sleep 3s;
ps -ef|grep gmeme|grep mine|grep -v grep;
```

Then run

```
./startMiner.sh
```
