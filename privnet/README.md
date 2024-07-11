# Private Ethereum network (privnet)

Mainly, this document is based on
https://geth.ethereum.org/docs/fundamentals/private-network, with some 
alterations added. It helps to set up a testing private Ethereum network (privnet) 
consisting of two nodes and a bootnode service running as a standalone instance.
Both nodes will run on the local machine, using the same genesis block and
network ID. The data directories for each node will be named `node1` and `node2`. 
Privnet uses the developer tool `bootnode`, and the `bootnode` directory stores
some data for it. Each node uses the bootnode as an entry point. 
`Node1` functions as a signer with Clique as the consensus algorithm, 
while `node2` serves as a simple RPC node.

Here are the instructions for running a private Ethereum network (privnet)
based on the specifications mentioned above:

1. Build `geth` and other necessary binaries:
   ```
   $ cd go-ethereum
   $ make all
   ```

2. Ensure that ports 30305, 30306, and 30307 are not in use on your 
   localhost (127.0.0.1). Also, ensure that RPC ports 8552 and 8553 are 
   not being used.

3. Start the private network by running `make privnet_start`. This command, if
   running from scratch, initializes the database for each node with genesis block
   inside it based on the [pre-configured initialization files](#reinitialize-privnet).
   If running with an existing database, no initialization is being performed.
   This command further runs the privnet with the described configuration.

   Now you can look into the files `privnet/single/node1/geth_node.log` and
   `privnet/single/node2/geth_node.log` to see the logs. Or you can use the next command:
   ```
   tail -f ./privnet/single/node1/geth_node.log
   ```
   Expected node logs looks like the following:
   <details>
    <summary>Node 1 (Clique consensus node) genesis initialisation logs</summary>
    
   ```
   INFO [09-26|10:58:04.027] Maximum peer count                       ETH=50 LES=0 total=50
   INFO [09-26|10:58:04.029] Smartcard socket not found, disabling    err="stat /run/pcscd/pcscd.comm: no such file or directory"
   INFO [09-26|10:58:04.030] Defaulting to pebble as the backing database 
   INFO [09-26|10:58:04.030] Allocated cache and file handles         database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata cache=512.00MiB handles=2048
   INFO [09-26|10:58:04.045] Opened ancient database                  database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata/ancient/chain readonly=false
   INFO [09-26|10:58:04.045] State schema set to default              scheme=hash
   INFO [09-26|10:58:04.045] Freezer shutting down 
   INFO [09-26|10:58:04.047] Set global gas cap                       cap=50,000,000
   INFO [09-26|10:58:04.047] Initializing the KZG library             backend=gokzg
   INFO [09-26|10:58:04.077] Using pebble as the backing database 
   INFO [09-26|10:58:04.077] Allocated cache and file handles         database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata cache=16.00MiB  handles=16
   INFO [09-26|10:58:04.088] Opened ancient database                  database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata/ancient/chain readonly=false
   INFO [09-26|10:58:04.088] State schema set to default              scheme=hash
   INFO [09-26|10:58:04.088] Writing custom genesis block 
   INFO [09-26|10:58:04.089] Persisted trie from memory database      nodes=3 size=411.00B time="879.578µs" gcnodes=0 gcsize=0.00B gctime=0s livenodes=0 livesize=0.00B
   INFO [09-26|10:58:04.100] Successfully wrote genesis state         database=chaindata hash=70ce01..8d4317
   INFO [09-26|10:58:04.100] Defaulting to pebble as the backing database 
   INFO [09-26|10:58:04.100] Allocated cache and file handles         database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/lightchaindata cache=16.00MiB  handles=16
   INFO [09-26|10:58:04.119] Opened ancient database                  database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/lightchaindata/ancient/chain readonly=false
   INFO [09-26|10:58:04.119] State schema set to default              scheme=hash
   INFO [09-26|10:58:04.119] Writing custom genesis block 
   INFO [09-26|10:58:04.120] Persisted trie from memory database      nodes=3 size=411.00B time="692.049µs" gcnodes=0 gcsize=0.00B gctime=0s livenodes=0 livesize=0.00B
   INFO [09-26|10:58:04.129] Successfully wrote genesis state         database=lightchaindata hash=70ce01..8d4317
   ```
   </details>
   <details>
    <summary>Node 1 (Clique consensus node) logs running from the genesis block</summary>
     
   ```
   INFO [09-26|10:58:04.347] Enabling metrics collection 
   INFO [09-26|10:58:04.348] Maximum peer count                       ETH=50 LES=0 total=50
   INFO [09-26|10:58:04.349] Smartcard socket not found, disabling    err="stat /run/pcscd/pcscd.comm: no such file or directory"
   INFO [09-26|10:58:04.351] Using pebble as the backing database 
   INFO [09-26|10:58:04.351] Allocated cache and file handles         database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata cache=512.00MiB handles=2048
   INFO [09-26|10:58:04.351] Opened ancient database                  database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata/ancient/chain readonly=true
   INFO [09-26|10:58:04.352] State scheme set to already existing     scheme=hash
   INFO [09-26|10:58:04.352] Set global gas cap                       cap=50,000,000
   INFO [09-26|10:58:04.352] Initializing the KZG library             backend=gokzg
   INFO [09-26|10:58:04.406] Allocated trie memory caches             clean=154.00MiB dirty=256.00MiB
   INFO [09-26|10:58:04.406] Using pebble as the backing database 
   INFO [09-26|10:58:04.406] Allocated cache and file handles         database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata cache=512.00MiB handles=2048
   INFO [09-26|10:58:04.416] Opened ancient database                  database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/chaindata/ancient/chain readonly=false
   INFO [09-26|10:58:04.416] Initialising Ethereum protocol           network=2,309,242,216 dbversion=<nil>
   INFO [09-26|10:58:04.418]  
   INFO [09-26|10:58:04.418] --------------------------------------------------------------------------------------------------------------------------------------------------------- 
   INFO [09-26|10:58:04.418] Chain ID:  2309242216 (unknown) 
   INFO [09-26|10:58:04.418] Consensus: Clique (proof-of-authority) 
   INFO [09-26|10:58:04.418]  
   INFO [09-26|10:58:04.418] Pre-Merge hard forks (block based): 
   INFO [09-26|10:58:04.418]  - Homestead:                   #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/homestead.md) 
   INFO [09-26|10:58:04.418]  - Tangerine Whistle (EIP 150): #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/tangerine-whistle.md) 
   INFO [09-26|10:58:04.418]  - Spurious Dragon/1 (EIP 155): #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/spurious-dragon.md) 
   INFO [09-26|10:58:04.418]  - Spurious Dragon/2 (EIP 158): #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/spurious-dragon.md) 
   INFO [09-26|10:58:04.418]  - Byzantium:                   #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/byzantium.md) 
   INFO [09-26|10:58:04.418]  - Constantinople:              #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/constantinople.md) 
   INFO [09-26|10:58:04.418]  - Petersburg:                  #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/petersburg.md) 
   INFO [09-26|10:58:04.418]  - Istanbul:                    #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/istanbul.md) 
   INFO [09-26|10:58:04.418]  - Muir Glacier:                #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/muir-glacier.md) 
   INFO [09-26|10:58:04.418]  - Berlin:                      #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/berlin.md) 
   INFO [09-26|10:58:04.418]  - London:                      #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/london.md) 
   INFO [09-26|10:58:04.418]  - Arrow Glacier:               #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/arrow-glacier.md) 
   INFO [09-26|10:58:04.418]  - Gray Glacier:                #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/gray-glacier.md) 
   INFO [09-26|10:58:04.418]  
   INFO [09-26|10:58:04.418] The Merge is not yet available for this network! 
   INFO [09-26|10:58:04.418]  - Hard-fork specification: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/paris.md 
   INFO [09-26|10:58:04.418]  
   INFO [09-26|10:58:04.418] Post-Merge hard forks (timestamp based): 
   INFO [09-26|10:58:04.418]  
   INFO [09-26|10:58:04.418] --------------------------------------------------------------------------------------------------------------------------------------------------------- 
   INFO [09-26|10:58:04.418]  
   INFO [09-26|10:58:04.418] Loaded most recent local block           number=0 hash=70ce01..8d4317 td=1 age=54y6mo6d
   WARN [09-26|10:58:04.418] Failed to load snapshot                  err="missing or corrupted snapshot"
   INFO [09-26|10:58:04.431] Rebuilding state snapshot 
   INFO [09-26|10:58:04.432] Resuming state snapshot generation       root=fd8821..d6b191 accounts=0 slots=0 storage=0.00B dangling=0 elapsed="960.734µs"
   INFO [09-26|10:58:04.432] Initialized transaction indexer          limit=2,350,000
   INFO [09-26|10:58:04.432] Regenerated local transaction journal    transactions=0 accounts=0
   INFO [09-26|10:58:04.433] Generated state snapshot                 accounts=2 slots=0 storage=94.00B dangling=0 elapsed=2.349ms
   INFO [09-26|10:58:04.438] Gasprice oracle is ignoring threshold set threshold=2
   WARN [09-26|10:58:04.440] Engine API enabled                       protocol=eth
   WARN [09-26|10:58:04.440] Engine API started but chain not configured for merge yet 
   INFO [09-26|10:58:04.440] Starting peer-to-peer node               instance=Geth/v1.13.1-stable-37177a8c/linux-amd64/go1.19.4
   INFO [09-26|10:58:04.440] Stored checkpoint snapshot to disk       number=0 hash=70ce01..8d4317
   INFO [09-26|10:58:04.511] New local node record                    seq=1,695,715,084,511 id=dcde4c3bacc6934f ip=127.0.0.1 udp=30306 tcp=30306
   INFO [09-26|10:58:04.512] Started P2P networking                   self=enode://ea80ec1bd9241833d6738d919d89a31bedeb9e65cc47018516e8a75f859d601f6431be5980a284be914ce739c33a5eaaa38b09e8c2d653fc09744ed83e37a050@127.0.0.1:30306
   INFO [09-26|10:58:04.512] IPC endpoint opened                      url=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth.ipc
   INFO [09-26|10:58:04.512] Generated JWT secret                     path=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node1/geth/jwtsecret
   INFO [09-26|10:58:04.513] WebSocket enabled                        url=ws://127.0.0.1:8552
   INFO [09-26|10:58:04.513] HTTP server started                      endpoint=127.0.0.1:8552 auth=true prefix= cors=localhost vhosts=localhost
   INFO [09-26|10:58:05.251] Unlocked account                         address=0x625eAFa3473492007C0dD331E23B1035f6a7FB64
   INFO [09-26|10:58:05.252] Legacy pool tip threshold updated        tip=0
   INFO [09-26|10:58:05.252] Legacy pool tip threshold updated        tip=1,000,000,000
   INFO [09-26|10:58:05.252] Commit new sealing work                  number=1 sealhash=0f0f03..c0b4be txs=0 gas=0 fees=0 elapsed="70.258µs"
   INFO [09-26|10:58:05.253] Successfully sealed new block            number=1 sealhash=0f0f03..c0b4be hash=7033dc..f158d5 elapsed=1.763ms
   INFO [09-26|10:58:05.254] Commit new sealing work                  number=2 sealhash=5ea68e..e71378 txs=0 gas=0 fees=0 elapsed="166.691µs"
   INFO [09-26|10:58:10.004] Successfully sealed new block            number=2 sealhash=5ea68e..e71378 hash=30077c..c0baed elapsed=4.750s
   INFO [09-26|10:58:10.005] Commit new sealing work                  number=3 sealhash=642be3..2acdbb txs=0 gas=0 fees=0 elapsed="802.001µs"
   INFO [09-26|10:58:14.537] Looking for peers                        peercount=1 tried=0 static=0
   INFO [09-26|10:58:15.004] Successfully sealed new block            number=3 sealhash=642be3..2acdbb hash=b505c3..096967 elapsed=4.999s
   INFO [09-26|10:58:15.005] Commit new sealing work                  number=4 sealhash=70a475..531131 txs=0 gas=0 fees=0 elapsed="899.171µs"
   INFO [09-26|10:58:20.004] Successfully sealed new block            number=4 sealhash=70a475..531131 hash=01ec7f..79198c elapsed=4.998s
   INFO [09-26|10:58:20.005] Commit new sealing work                  number=5 sealhash=e39ea0..c10e41 txs=0 gas=0 fees=0 elapsed="969.197µs"
   INFO [09-26|10:58:24.557] Looking for peers                        peercount=1 tried=0 static=0
   INFO [09-26|10:58:25.004] Successfully sealed new block            number=5 sealhash=e39ea0..c10e41 hash=a9148d..c7ca3f elapsed=4.998s
   INFO [09-26|10:58:25.005] Commit new sealing work                  number=6 sealhash=b0fc2c..ed615f txs=0 gas=0 fees=0 elapsed=1.167ms
   INFO [09-26|10:58:30.004] Successfully sealed new block            number=6 sealhash=b0fc2c..ed615f hash=d4a66a..0c9c29 elapsed=4.998s
   INFO [09-26|10:58:30.005] Commit new sealing work                  number=7 sealhash=ee8b38..1cb14e txs=0 gas=0 fees=0 elapsed=1.262ms
   INFO [09-26|10:58:34.577] Looking for peers                        peercount=1 tried=0 static=0
   INFO [09-26|10:58:35.003] Successfully sealed new block            number=7 sealhash=ee8b38..1cb14e hash=7b8dee..3e3f8b elapsed=4.997s
   INFO [09-26|10:58:35.004] Commit new sealing work                  number=8 sealhash=736ca1..40d810 txs=0 gas=0 fees=0 elapsed=1.115ms
   INFO [09-26|10:58:40.004] Successfully sealed new block            number=8 sealhash=736ca1..40d810 hash=d988d8..808903 elapsed=4.999s
   INFO [09-26|10:58:40.005] Commit new sealing work                  number=9 sealhash=d2b37e..1cfb6a txs=0 gas=0 fees=0 elapsed="848.455µs"
   INFO [09-26|10:58:44.596] Looking for peers                        peercount=1 tried=0 static=0
   INFO [09-26|10:58:45.013] Successfully sealed new block            number=9 sealhash=d2b37e..1cfb6a hash=cfbf43..3914fb elapsed=5.007s
   INFO [09-26|10:58:45.014] Commit new sealing work                  number=10 sealhash=3c4ee4..c7fc00 txs=0 gas=0 fees=0 elapsed="879.85µs"
   ```
   </details>
   <details>
    <summary>Node 2 (RPC node) logs running from the genesis block</summary>
     
   ```
   INFO [09-26|10:58:04.344] Enabling metrics collection 
   INFO [09-26|10:58:04.345] Maximum peer count                       ETH=50 LES=0 total=50
   INFO [09-26|10:58:04.346] Smartcard socket not found, disabling    err="stat /run/pcscd/pcscd.comm: no such file or directory"
   INFO [09-26|10:58:04.347] Using pebble as the backing database 
   INFO [09-26|10:58:04.348] Allocated cache and file handles         database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node2/geth/chaindata cache=512.00MiB handles=2048
   INFO [09-26|10:58:04.348] Opened ancient database                  database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node2/geth/chaindata/ancient/chain readonly=true
   INFO [09-26|10:58:04.348] State scheme set to already existing     scheme=hash
   INFO [09-26|10:58:04.348] Set global gas cap                       cap=50,000,000
   INFO [09-26|10:58:04.349] Initializing the KZG library             backend=gokzg
   INFO [09-26|10:58:04.400] Allocated trie memory caches             clean=154.00MiB dirty=256.00MiB
   INFO [09-26|10:58:04.400] Using pebble as the backing database 
   INFO [09-26|10:58:04.400] Allocated cache and file handles         database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node2/geth/chaindata cache=512.00MiB handles=2048
   INFO [09-26|10:58:04.408] Opened ancient database                  database=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node2/geth/chaindata/ancient/chain readonly=false
   INFO [09-26|10:58:04.408] Initialising Ethereum protocol           network=2,309,242,216 dbversion=<nil>
   INFO [09-26|10:58:04.410]  
   INFO [09-26|10:58:04.410] --------------------------------------------------------------------------------------------------------------------------------------------------------- 
   INFO [09-26|10:58:04.410] Chain ID:  2309242216 (unknown) 
   INFO [09-26|10:58:04.410] Consensus: Clique (proof-of-authority) 
   INFO [09-26|10:58:04.410]  
   INFO [09-26|10:58:04.410] Pre-Merge hard forks (block based): 
   INFO [09-26|10:58:04.410]  - Homestead:                   #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/homestead.md) 
   INFO [09-26|10:58:04.410]  - Tangerine Whistle (EIP 150): #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/tangerine-whistle.md) 
   INFO [09-26|10:58:04.410]  - Spurious Dragon/1 (EIP 155): #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/spurious-dragon.md) 
   INFO [09-26|10:58:04.410]  - Spurious Dragon/2 (EIP 158): #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/spurious-dragon.md) 
   INFO [09-26|10:58:04.410]  - Byzantium:                   #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/byzantium.md) 
   INFO [09-26|10:58:04.410]  - Constantinople:              #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/constantinople.md) 
   INFO [09-26|10:58:04.410]  - Petersburg:                  #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/petersburg.md) 
   INFO [09-26|10:58:04.410]  - Istanbul:                    #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/istanbul.md) 
   INFO [09-26|10:58:04.410]  - Muir Glacier:                #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/muir-glacier.md) 
   INFO [09-26|10:58:04.410]  - Berlin:                      #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/berlin.md) 
   INFO [09-26|10:58:04.410]  - London:                      #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/london.md) 
   INFO [09-26|10:58:04.410]  - Arrow Glacier:               #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/arrow-glacier.md) 
   INFO [09-26|10:58:04.410]  - Gray Glacier:                #0        (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/gray-glacier.md) 
   INFO [09-26|10:58:04.410]  
   INFO [09-26|10:58:04.410] The Merge is not yet available for this network! 
   INFO [09-26|10:58:04.410]  - Hard-fork specification: https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/paris.md 
   INFO [09-26|10:58:04.410]  
   INFO [09-26|10:58:04.410] Post-Merge hard forks (timestamp based): 
   INFO [09-26|10:58:04.410]  
   INFO [09-26|10:58:04.410] --------------------------------------------------------------------------------------------------------------------------------------------------------- 
   INFO [09-26|10:58:04.410]  
   INFO [09-26|10:58:04.410] Loaded most recent local block           number=0 hash=70ce01..8d4317 td=1 age=54y6mo6d
   WARN [09-26|10:58:04.410] Failed to load snapshot                  err="missing or corrupted snapshot"
   INFO [09-26|10:58:04.415] Rebuilding state snapshot 
   INFO [09-26|10:58:04.416] Resuming state snapshot generation       root=fd8821..d6b191 accounts=0 slots=0 storage=0.00B dangling=0 elapsed=1.239ms
   INFO [09-26|10:58:04.416] Regenerated local transaction journal    transactions=0 accounts=0
   INFO [09-26|10:58:04.416] Initialized transaction indexer          limit=2,350,000
   INFO [09-26|10:58:04.417] Generated state snapshot                 accounts=2 slots=0 storage=94.00B dangling=0 elapsed=2.509ms
   INFO [09-26|10:58:04.424] Gasprice oracle is ignoring threshold set threshold=2
   WARN [09-26|10:58:04.426] Engine API enabled                       protocol=eth
   WARN [09-26|10:58:04.426] Engine API started but chain not configured for merge yet 
   INFO [09-26|10:58:04.426] Starting peer-to-peer node               instance=Geth/v1.13.1-stable-37177a8c/linux-amd64/go1.19.4
   INFO [09-26|10:58:04.428] Stored checkpoint snapshot to disk       number=0 hash=70ce01..8d4317
   INFO [09-26|10:58:04.464] New local node record                    seq=1,695,715,084,464 id=997395d56a658731 ip=127.0.0.1 udp=30307 tcp=30307
   INFO [09-26|10:58:04.465] Started P2P networking                   self=enode://4670b6104e5a3bcacf40d64bbf922ca6ad8bb7a06c5b511e354cd1fc00325b4602420a222fe1e338c97724f3a1fb795532aaabc10af30b6a87c9d252be08034a@127.0.0.1:30307
   INFO [09-26|10:58:04.465] IPC endpoint opened                      url=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node2/geth.ipc
   INFO [09-26|10:58:04.465] Generated JWT secret                     path=/home/anna/Documents/GitProjects/bane-labs/go-ethereum/privnet/single/node2/geth/jwtsecret
   INFO [09-26|10:58:04.466] WebSocket enabled                        url=ws://127.0.0.1:8553
   INFO [09-26|10:58:04.466] HTTP server started                      endpoint=127.0.0.1:8553 auth=true prefix= cors=localhost vhosts=localhost
   INFO [09-26|10:58:05.192] Unlocked account                         address=0x745c8f1AF649651f46DcAEc2C6EB94068843AE96
   INFO [09-26|10:58:14.478] Block synchronisation started 
   INFO [09-26|10:58:14.488] Looking for peers                        peercount=1 tried=1 static=0
   INFO [09-26|10:58:14.493] Syncing: state download in progress      synced=30.06% state=196.00B accounts=1@196.00B slots=0@0.00B codes=0@0.00B eta=24.336ms
   INFO [09-26|10:58:14.495] Imported new chain segment               number=2 hash=30077c..c0baed blocks=2 txs=0 mgas=0.000 elapsed=6.913ms mgasps=0.000 triedirty=0.00B
   INFO [09-26|10:58:14.496] Syncing: chain download in progress      synced=+Inf%  chain=18.00B headers=2@6.00B bodies=2@6.00B receipts=2@6.00B eta=-8.349ms
   INFO [09-26|10:58:14.496] Syncing: state download in progress      synced=43.85% state=196.00B accounts=1@196.00B slots=0@0.00B codes=0@0.00B eta=16.675ms
   WARN [09-26|10:58:14.497] Unexpected account range packet          peer=dcde4c3b reqid=2,970,700,287,221,458,280
   WARN [09-26|10:58:14.497] Synchronisation failed, retrying         err="sync cancelled"
   WARN [09-26|10:58:15.006] Snap syncing, discarded propagated block number=3 hash=b505c3..096967
   INFO [09-26|10:58:24.511] Looking for peers                        peercount=1 tried=0 static=0
   INFO [09-26|10:58:24.513] Syncing: state download in progress      synced=43.85% state=196.00B accounts=1@196.00B slots=0@0.00B codes=0@0.00B eta=12.844s
   INFO [09-26|10:58:24.520] Syncing: chain download in progress      synced=100.00% chain=18.00B headers=4@6.00B bodies=2@6.00B receipts=2@6.00B eta=0s
   INFO [09-26|10:58:24.521] Syncing: state download in progress      synced=62.52%  state=392.00B accounts=2@392.00B slots=0@0.00B codes=0@0.00B eta=6.017s
   WARN [09-26|10:58:24.522] Unexpected account range packet          peer=dcde4c3b reqid=2,282,476,590,775,666,788
   INFO [09-26|10:58:24.528] Syncing: state download in progress      synced=100.00% state=392.00B accounts=2@392.00B slots=0@0.00B codes=0@0.00B eta=-239ns
   INFO [09-26|10:58:24.528] Syncing: state healing in progress       accounts=0@0.00B   slots=0@0.00B codes=0@0.00B nodes=0@0.00B pending=0
   INFO [09-26|10:58:24.531] Rebuilding state snapshot 
   INFO [09-26|10:58:24.533] Committed new head block                 number=2 hash=30077c..c0baed
   INFO [09-26|10:58:24.533] Resuming state snapshot generation       root=fd8821..d6b191 accounts=0         slots=0       storage=0.00B  dangling=0 elapsed=1.799ms
   INFO [09-26|10:58:24.535] Generated state snapshot                 accounts=2         slots=0       storage=96.00B dangling=0 elapsed=3.445ms
   INFO [09-26|10:58:24.541] Imported new chain segment               number=4 hash=01ec7f..79198c blocks=2 txs=0 mgas=0.000 elapsed=7.212ms mgasps=0.000 triedirty=0.00B
   WARN [09-26|10:58:25.005] Snap syncing, discarded propagated block number=5 hash=a9148d..c7ca3f
   INFO [09-26|10:58:27.524] Imported new chain segment               number=5 hash=a9148d..c7ca3f blocks=1 txs=0 mgas=0.000 elapsed=3.146ms mgasps=0.000 triedirty=0.00B
   INFO [09-26|10:58:27.525] Syncing: chain download in progress      synced=250.00% chain=18.00B headers=5@6.00B bodies=5@6.00B receipts=5@6.00B eta=-7.822s
   INFO [09-26|10:58:27.525] Snap sync complete, auto disabling 
   INFO [09-26|10:58:30.008] Imported new chain segment               number=6 hash=d4a66a..0c9c29 blocks=1 txs=0 mgas=0.000 elapsed=3.134ms mgasps=0.000 triedirty=0.00B
   INFO [09-26|10:58:34.532] Looking for peers                        peercount=1 tried=0 static=0
   INFO [09-26|10:58:35.008] Imported new chain segment               number=7 hash=7b8dee..3e3f8b blocks=1 txs=0 mgas=0.000 elapsed=2.941ms mgasps=0.000 triedirty=0.00B
   INFO [09-26|10:58:40.008] Imported new chain segment               number=8 hash=d988d8..808903 blocks=1 txs=0 mgas=0.000 elapsed=2.597ms mgasps=0.000 triedirty=0.00B
   ```
   </details>
   <details>
    <summary>Bootnode logs running from scratch</summary>
    
   ```
   enode://5660d7868940969b7ce79c2604918fc7c3b443c0e446cb2fbfe9cb121d9925dc812e83c2bbd61ab37b0865a8475e367f89431ebd847a73dccbe132e523e3a83b@127.0.0.1:0?discport=30305
   Note: you're using cmd/bootnode, a developer tool.
   We recommend using a regular node as bootstrap node for production deployments.
   INFO [09-26|10:58:04.328] New local node record                    seq=1,695,715,084,327 id=e200fb100c5aa38e ip=<nil> udp=0 tcp=0
   TRACE[09-26|10:58:04.465] << PING/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.465] >> PONG/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.465] >> PING/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.465] << PING/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.465] >> PONG/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.465] >> PING/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.466] << PONG/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.466] << PONG/v4                               id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.512] << PING/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.512] >> PONG/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.512] >> PING/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.512] << PING/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.512] >> PONG/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.512] >> PING/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.513] << PONG/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.513] << PONG/v4                               id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:04.966] << FINDNODE/v4                           id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.966] >> NEIGHBORS/v4                          id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.966] << FINDNODE/v4                           id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:04.966] >> NEIGHBORS/v4                          id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:05.013] << FINDNODE/v4                           id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:05.013] >> NEIGHBORS/v4                          id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:05.013] << FINDNODE/v4                           id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:05.013] >> NEIGHBORS/v4                          id=dcde4c3bacc6934f addr=127.0.0.1:30306 err=nil
   TRACE[09-26|10:58:05.468] << FINDNODE/v4                           id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:05.468] >> NEIGHBORS/v4                          id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   TRACE[09-26|10:58:05.469] << FINDNODE/v4                           id=997395d56a658731 addr=127.0.0.1:30307 err=nil
   ```
  </details>

4. To stop the private network, use the command `make privnet_stop`. This command
   kills the running privnet processes (node1, node2 and bootnode) and *does not*
   affect the database or network settings. So that it's possible to start the
   same network with the existing database using `make privnet_run` afterward.

5. To remove the existing privnet database, use the command `make privnet_clean`.
   It removes the database files located in the `privnet` directory and *does not*
   affect the network settings files (accounts, passwords, genesis settings,
   network ID and etc.). So that it's possible to start a fresh privnet with the
   same network settings, accounts and genesis block.

## Commands in JavaScript console

While privnet is started, it is now possible to attach a Javascript console 
to either node to query the network properties:
```
./build/bin/geth attach privnet/single/node1/geth.ipc
```
Once the Javascript console is running, check that the node is connected 
to one other peer. It should be equal 1.
```
net.peerCount
```

You can check the account balance for each account (find the address in the 
console where you’ve started privnet):
```
eth.getBalance('745c8f1af649651f46dcaec2c6eb94068843ae96')
```

You can send a transaction between these accounts:
```
eth.sendTransaction({
from: '625eafa3473492007c0dd331e23b1035f6a7fb64',
to: '745c8f1af649651f46dcaec2c6eb94068843ae96',
value: 250,
gas_price: 10,
gas: 30000
});
```

## Reinitialize privnet

Privnet configuration includes a set of solid files containing network settings and
nodes accounts/passwords. To simplify development process, it is supposed not to
change these configuration files from run to run to keep the privnet as stable
as possible in development environment. However, it's possible to reinitialize
all configuration information if needed. Privnet reinitialization includes:
 * Node accounts/passwords regeneration (`privnet/single/node[1,2]/node_address.txt`,
   `privnet/single/node[1,2]/password.txt`, `privnet/single/node[1,2]/keystore`, `privnet/single/bootnode/bootnode.key`, `privnet/single/bootnode/bootnode_address.txt`);
 * Network ID regeneration (`privnet/single/networkid.txt`);
 * Genesis block settings regeneration (`privnet/single/node[1,2]/genesis_privnet.json`);
 * Corresponding network configuration file update (`privnet/single/config.json`).

Note, that the reinitialisation operation is not supposed to be used during
standard development flow. To reinitialize the entire private network, please
follow the steps below:

1. Reinitialize the private network by running `make privnet_init`. It cleans 
   the files mentioned above and generates the new ones.
   
   <details>
    <summary>Example of reinitialization logs</summary>
    
   ```
   Killing bootnode processes
   bootnode: no process found
   Killing nodes processes
   geth: no process found
   Cleaning the nodes database files from ./privnet
   Generate  genesis_privnet.json file
   Network ID is 2309261357
   Generate bootnode
   Create accounts
   INFO [09-26|13:57:21.034] Maximum peer count                       ETH=50 LES=0 total=50
   INFO [09-26|13:57:21.035] Smartcard socket not found, disabling    err="stat /run/pcscd/pcscd.comm: no such file or directory"
   
   Your new key was generated
   
   Public address of the key:   0x9F32FE98fFe189139500Fa10b7A42bD384F3dd19
   Path of the secret key file: privnet/single/node1/keystore/UTC--2023-09-26T10-57-21.036319562Z--9f32fe98ffe189139500fa10b7a42bd384f3dd19
   
   - You can share your public address with anyone. Others need it to interact with you.
   - You must NEVER share the secret key with anyone! The key controls access to your funds!
   - You must BACKUP your key file! Without the key, it's impossible to access account funds!
   - You must REMEMBER your password! Without the password, it's impossible to decrypt the key!
   
   Account node1: 9f32fe98ffe189139500fa10b7a42bd384f3dd19
   INFO [09-26|13:57:22.282] Maximum peer count                       ETH=50 LES=0 total=50
   INFO [09-26|13:57:22.284] Smartcard socket not found, disabling    err="stat /run/pcscd/pcscd.comm: no such file or directory"
   
   Your new key was generated
   
   Public address of the key:   0xD44cB7Ecf44C3878DD1028FD658501427Bd2728D
   Path of the secret key file: privnet/single/node2/keystore/UTC--2023-09-26T10-57-22.284551374Z--d44cb7ecf44c3878dd1028fd658501427bd2728d
   
   - You can share your public address with anyone. Others need it to interact with you.
   - You must NEVER share the secret key with anyone! The key controls access to your funds!
   - You must BACKUP your key file! Without the key, it's impossible to access account funds!
   - You must REMEMBER your password! Without the password, it's impossible to decrypt the key!
   
   Account node2: d44cb7ecf44c3878dd1028fd658501427bd2728d
   Copy genesis_privnet.json into nodes
   OK! For starting use 'make privnet_start'
   ```
   </details>

2. Commit changes.

## Privnet setups

There are several configurations of privnet:
1. Single consensus (AKA miner) node + one non-miner RPC node. Can be run with `make privnet_start` and stopped with `make privnet_stop`.
2. Four consensus nodes + one PPC node. Can be run with `make privnet_start_four` and stopped with `make privnet_stop`.
3. Seven consensus nodes + one RPC node. Can be run with `make privnet_start_seven` and stopped with `make privnet_stop`.

Node's databases, accounts and logs can be found in the setup-specific path, i.e. `./privnet/single/node[1,2]` for single-node consensus setup,
`./privnet/four/node[1-5]` for four-nodes consensus setup and `./privnet/seven/node[1-8]` for seven-node consensus setup.