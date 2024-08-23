# Running a Node

This document contains step-by-step instructions for running a geth node in MimNetwork.

## Hardware Requirements

The following are the minimum hardware requirements:

* CPU with 2+ cores
* 4GB RAM
* 200GB free storage space
* 8 MBit/sec download Internet service

## 1. Building or Downloading Geth Binary

### Build the source

Building `geth` requires both a Go (version 1.19 or later) and a C compiler. Feel free to install them with the package manager of your choice.

Once the dependencies are installed, run

```
make geth
```

or, build the full suite of utilities:

```
make all
```

## 2. Initializing Geth Database

Download the latest .json configuration file from [https://github.com/tech-memecore/mimnetwork-private-sharing/tree/master/privnet/seven](https://github.com/tech-memecore/mimnetwork-private-sharing/tree/master/privnet/seven).

To create a blockchain node that uses this genesis block, first use geth init to import and set the canonical genesis block for the new chain. This requires the path to the configuration file to be passed as an argument.

&#x20;`--datadir` is the target destination for the node database. Here we use `./nodes/node1`:

Privnet

```
./geth init --datadir ./nodes/node1 ./genesis_privnet.json
```

## 3. Initializing Node Account

You can create a new account or import an existing account for your node operation. Seed nodes don't need node account.

### Create a new account

Create your node account with the following command. A password is required to be entered during the process. The resulting account is placed in the specified `--datadir` under the `keystore` path.

```
./geth --datadir ./nodes/node1 account new
```

### Import your existing account

Import your existing account with the private key and remember to replace the `./your/privateKey.txt` parameter.

```
./geth account import --datadir ./nodes/node1 ./your/privateKey.txt
```

## 4. Running Seed Node

A seed node is a network member that does not participate in the consensus process. This node can be used to interact with the MimNetwork, including: creating accounts, transferring funds, deploying and interacting with contracts, and querying node APIs.

Create the `startSeed.sh` file in the same folder of `geth`. You may need to change the `P2P/HTTP/RPC/WS` ports to avoid conflicts. Please note that the port configuration for the JSON-RPC interface should be set to httpport, not rpcport. Additionally, remember to change `extip` to your own IP address if you want other nodes to be able to find yours. You can refer to [https://geth.ethereum.org/docs/fundamentals/command-line-options](https://geth.ethereum.org/docs/fundamentals/command-line-options) for more details about start options.

This script expects node DB directory to be `./node/node1`.

#### Privnet:

```
#!/bin/bash
​
node="nodes/node1"
​
port=30301
httpport=8551
rpcport=8561
wsport=8571
extip=127.0.0.1
​
echo "$node and miner is $miner, rpc port $rpcport, p2p port $port"
​
nohup ./geth \
--networkid 2312251829 \
--nat extip:$extip \
--port $port \
--authrpc.port $rpcport \
--identity=$node \
--maxpeers=50 \
--syncmode full \
--gcmode archive \
--datadir $node \
--bootnodes "enode://83dfefac36bf84cc121462edc91c14b513488383b24a8030f57aea9b5d3318701a775a90ff9db177573a6dc87ab78cc9e84858fc570a353a21f705c5c40f5a05@127.0.0.1:30306" \
--http.api admin,eth,debug,miner,net,txpool,personal,web3 \
--http --http.addr 0.0.0.0 --http.port $httpport --http.vhosts "*" --http.corsdomain '*' \
--ws --ws.addr 0.0.0.0 --ws.port $wsport --ws.api eth,net,web3 --ws.origins '*'  \
--verbosity 3  >> $node/node.log 2>&1 &
​
sleep 3s;
ps -ef|grep geth|grep mine|grep -v grep;
```

## 5. Running Miner Node

A miner node participates in the PoSA consensus. If you want to register as a candidate for PoSA validators, you need to run a miner node.

Create the `startMiner.sh` file in the same folder of `geth`. You may need to change the `P2P/RPC` ports to avoid conflicts. Additionally, remember to change `extip` if you want other nodes to be able to find yours. You can refer to [https://geth.ethereum.org/docs/fundamentals/command-line-options](https://geth.ethereum.org/docs/fundamentals/command-line-options) for more details about start options.

When the inputing node index is set to 1, this script requires the node address to be placed at `nodes/node1/node_address.txt`, the node password to be placed at `nodes/node1/password.txt` and the node DB directory to be placed at `./node/node1`.

#### Privnet:

```
#!/bin/bash

echo "input node index"
read nodeIndex
node="nodes/node$nodeIndex"

startP2PPort=30300
startRPCPort=8561

port=`expr $startP2PPort + $nodeIndex`
rpcport=`expr $startRPCPort + $nodeIndex`
extip=127.0.0.1

miner=$(<$node/node_address.txt)
echo "$node and miner is $miner, rpc port $rpcport, p2p port $port"

nohup ./geth \
--networkid 2312251829 \
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
--bootnodes "enode://83dfefac36bf84cc121462edc91c14b513488383b24a8030f57aea9b5d3318701a775a90ff9db177573a6dc87ab78cc9e84858fc570a353a21f705c5c40f5a05@127.0.0.1:30306" \
--verbosity 3  >> $node/node.log 2>&1 &

sleep 3s;
ps -ef|grep geth|grep mine|grep -v grep;
```

Then run

```
./startMiner.sh
```
