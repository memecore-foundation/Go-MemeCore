# Private MemeCore network (privnet)

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

1. Build `gmeme` and other necessary binaries:
   ```
   $ cd go-memecore
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

   Now you can look into the files `privnet/single/node1/gmeme_node.log` and
   `privnet/single/node2/gmeme_node.log` to see the logs. Or you can use the next command:
   ```
   tail -f ./privnet/single/node1/gmeme_node.log
   ```

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
./build/bin/gmeme attach privnet/single/node1/gmeme.ipc
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
   gmeme: no process found
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
