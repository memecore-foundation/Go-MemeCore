## Go MemeCore

Golang execution layer implementation of the MemeCore protocol (Ethereum-compatible).

**Current Version: v1.15.1-stable**

### Key Features
- EIP-4844 Blob Transaction Support (Cancun hardfork)
- PoSA (Proof of Staked Authority) Consensus Engine
- GasTree, RewardTree, CanPraTree Hardfork Support
- Full Ethereum JSON-RPC API Compatibility

## Building the source

For prerequisites and detailed build instructions please read the [Installation Instructions](https://geth.ethereum.org/docs/getting-started/installing-geth).

For reference, it is technically based on geth, and the standard documentation for geth is compatible with gmeme. Therefore, please note that some of the documentation links to geth-based documentation, and you can recognize it as gmeme instead of geth.

Building `gmeme` requires both a Go (version 1.23 or later) and a C compiler. You can install
them using your favourite package manager. Once the dependencies are installed, run

```shell
make gmeme
```

or, to build the full suite of utilities:

```shell
make all
```

## Executables

The go-memecore project comes with several wrappers/executables found in the `cmd`
directory.

|  Command   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| :--------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`gmeme`** | Our main MemeCore CLI client. It is the entry point into the MemeCore network (main-, test- or private net), capable of running as a full node (default) or archive node (retaining all historical state). It can be used by other processes as a gateway into the MemeCore network via JSON RPC endpoints exposed on top of HTTP, WebSocket and/or IPC transports. `gmeme --help` and the [CLI page](https://geth.ethereum.org/docs/fundamentals/command-line-options) for command line options. |
|   `clef`   | Stand-alone signing tool, which can be used as a backend signer for `gmeme`. Can be integrated with external signers including HSM (Hardware Security Module).                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `bootnode` | Stripped down version of the MemeCore client that only participates in the network node discovery protocol, but does not run any of the higher level application protocols. It can be used as a lightweight bootstrap node to aid in finding peers in private networks.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|  `devp2p`  | Utilities to interact with nodes on the networking layer, without running a full blockchain.                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|  `abigen`  | Source code generator to convert Ethereum contract definitions into easy-to-use, compile-time type-safe Go packages. It operates on plain [Ethereum contract ABIs](https://docs.soliditylang.org/en/develop/abi-spec.html) with expanded functionality if the contract bytecode is also available. However, it also accepts Solidity source files, making development much more streamlined. Please see our [Native DApps](https://geth.ethereum.org/docs/developers/dapp-developer/native-bindings) page for details.                                  |
|   `evm`    | Developer utility version of the EVM (Ethereum Virtual Machine) that is capable of running bytecode snippets within a configurable environment and execution mode. Its purpose is to allow isolated, fine-grained debugging of EVM opcodes (e.g. `evm --code 60ff60ff --debug run`).                                                                                                                                                                                                                                               |
| `rlpdump`  | Developer utility tool to convert binary RLP ([Recursive Length Prefix](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp)) dumps (data encoding used by the Ethereum protocol both network as well as consensus wise) to user-friendlier hierarchical representation (e.g. `rlpdump --hex CE0183FFFFFFC4C304050583616263`).                                                                                                                                                                                |

## Running `gmeme`

Going through all the possible command line flags is out of scope here (please consult our
[CLI Wiki page](https://geth.ethereum.org/docs/fundamentals/command-line-options)),
but we've enumerated a few common parameter combos to get you up to speed quickly
on how you can run your own `gmeme` instance.

### Hardware Requirements

Minimum:

* CPU with 4+ cores
* 8GB RAM
* 1TB free storage space to sync the Mainnet
* 8 MBit/sec download Internet service

Recommended:

* Fast CPU with 8+ cores
* 16GB+ RAM
* High-performance SSD with at least 1TB of free space
* 25+ MBit/sec download Internet service

### Full node on the main MemeCore network

By far the most common scenario is people wanting to simply interact with the MemeCore
network: create accounts; transfer funds; deploy and interact with contracts. For this
particular use case, the user doesn't care about years-old historical data, so we can
sync quickly to the current state of the network. To do so:

```shell
$ gmeme console
```

This command will:
 * Start `gmeme` in snap sync mode (default, can be changed with the `--syncmode` flag),
   causing it to download more data in exchange for avoiding processing the entire history
   of the MemeCore network, which is very CPU intensive.
 * Start the built-in interactive [JavaScript console](https://geth.ethereum.org/docs/interacting-with-geth/javascript-console),
   (via the trailing `console` subcommand) through which you can interact using [`web3` methods](https://github.com/ChainSafe/web3.js/blob/0.20.7/DOCUMENTATION.md)
   (note: the `web3` version bundled within `gmeme` is very old, and not up to date with official docs),
   as well as `gmeme`'s own [management APIs](https://geth.ethereum.org/docs/interacting-with-geth/rpc).
   This tool is optional and if you leave it out you can always attach it to an already running
   `gmeme` instance with `gmeme attach`.

### A Full node on the Insectarium test network

Transitioning towards developers, if you'd like to play around with creating MemeCore
contracts, you almost certainly would like to do that without any real money involved until
you get the hang of the entire system. In other words, instead of attaching to the main
network, you want to join the **test** network with your node, which is fully equivalent to
the main network, but with play-Meme only.

```shell
$ gmeme --insectarium console
```

The `console` subcommand has the same meaning as above and is equally
useful on the testnet too.

Specifying the `--insectarium` flag, however, will reconfigure your `gmeme` instance a bit:

- Instead of connecting to the main MemeCore network, the client will connect to the Insectarium
  test network, which uses different P2P bootnodes, different network IDs and genesis
  states.
- Instead of using the default data directory (`~/.memecore` on Linux for example), `gmeme`
  will nest itself one level deeper into a `insectarium` subfolder (`~/.memecore/insectarium` on
  Linux). Note, on OSX and Linux this also means that attaching to a running testnet node
  requires the use of a custom endpoint since `gmeme attach` will try to attach to a
  production node endpoint by default, e.g.,
  `gmeme attach <datadir>/insectarium/gmeme.ipc`. Windows users are not affected by
  this.

_Note: Although some internal protective measures prevent transactions from
crossing over between the main network and test network, you should always
use separate accounts for play and real money. Unless you manually move
accounts, `gmeme` will by default correctly separate the two networks and will not make any
accounts available between them._

## MemeCore Hardforks

MemeCore implements several custom hardforks to optimize network performance and economics:

### CanPraTree (Cancun + Prague)

Combines Ethereum's Cancun and Prague hardfork features (timestamp-based activation):
- **EIP-4844**: Blob transactions for Layer 2 data availability
- **EIP-1153**: Transient storage opcodes (TSTORE, TLOAD)
- **EIP-5656**: MCOPY opcode for efficient memory copy
- **EIP-6780**: SELFDESTRUCT restriction
- **EIP-2935**: Historical block hash storage in state
- **EIP-7702**: EOA code delegation support

_Note: EIP-4788 (parent beacon block root) is disabled for PoSA consensus._

### GasTree Hardfork

Reduces the initial base fee to improve transaction cost efficiency:
- Base fee reduced from 1500 gwei to 15 gwei (100x reduction)
- Configurable via `GasTreeForkBlock` in chain config

### RewardTree Hardfork

Adjusts block rewards for sustainable tokenomics:
- Block rewards reduced from 1125×10¹⁷ to 300×10¹⁷ wei
- Configurable via `RewardTreeForkBlock` in chain config

## PoSA Consensus

MemeCore uses Proof of Staked Authority (PoSA) consensus, combining elements of
Proof of Authority and Delegated Proof of Stake:

- Validators are selected based on staking amount
- Block production is scheduled in turns
- System contracts manage validator registration and rewards

### PoSA-specific Options

- `--posa.enable-event-logging`: Enable detailed event logging for PoSA consensus
- `--posa.signer-retry-interval`: Interval between retries for external signer (default: 500ms)
- `--posa.signer-retry-count`: Number of retries for external signer, -1 for infinite (default: -1)

## Configuration

As an alternative to passing the numerous flags to the `gmeme` binary, you can also pass a
configuration file via:

```shell
$ gmeme --config /path/to/your_config.toml
```

To get an idea of how the file should look like you can use the `dumpconfig` subcommand to
export your existing configuration:

```shell
$ gmeme --your-favourite-flags dumpconfig
```

### Docker quick start

One of the quickest ways to get MemeCore up and running on your machine is by using
Docker:

```shell
docker run -d --name memecore-node -v /Users/alice/memecore:/root \
           -p 8545:8545 -p 30303:30303 \
           memecore/gmeme
```

This will start `gmeme` in snap-sync mode with a DB memory allowance of 1GB, as the
above command does. It will also create a persistent volume in your home directory for
saving your blockchain as well as map the default ports.

Do not forget `--http.addr 0.0.0.0`, if you want to access RPC from other containers
and/or hosts. By default, `gmeme` binds to the local interface and RPC endpoints are not
accessible from the outside.

### Programmatically interfacing `gmeme` nodes

As a developer, sooner rather than later you'll want to start interacting with `gmeme` and the
MemeCore network via your own programs and not manually through the console. To aid
this, `gmeme` has built-in support for a JSON-RPC based APIs ([standard APIs](https://ethereum.github.io/execution-apis/api-documentation/)
and [`gmeme` specific APIs](https://geth.ethereum.org/docs/interacting-with-geth/rpc)).
These can be exposed via HTTP, WebSockets and IPC (UNIX sockets on UNIX based
platforms, and named pipes on Windows).

The IPC interface is enabled by default and exposes all the APIs supported by `gmeme`,
whereas the HTTP and WS interfaces need to manually be enabled and only expose a
subset of APIs due to security reasons. These can be turned on/off and configured as
you'd expect.

HTTP based JSON-RPC API options:

  * `--http` Enable the HTTP-RPC server
  * `--http.addr` HTTP-RPC server listening interface (default: `localhost`)
  * `--http.port` HTTP-RPC server listening port (default: `8545`)
  * `--http.api` API's offered over the HTTP-RPC interface (default: `eth,net,web3`)
  * `--http.corsdomain` Comma separated list of domains from which to accept cross-origin requests (browser enforced)
  * `--ws` Enable the WS-RPC server
  * `--ws.addr` WS-RPC server listening interface (default: `localhost`)
  * `--ws.port` WS-RPC server listening port (default: `8546`)
  * `--ws.api` API's offered over the WS-RPC interface (default: `eth,net,web3`)
  * `--ws.origins` Origins from which to accept WebSocket requests
  * `--ipcdisable` Disable the IPC-RPC server
  * `--ipcpath` Filename for IPC socket/pipe within the datadir (explicit paths escape it)

You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
connect via HTTP, WS or IPC to a `gmeme` node configured with the above flags and you'll
need to speak [JSON-RPC](https://www.jsonrpc.org/specification) on all transports. You
can reuse the same connection for multiple requests!

**Note: Please understand the security implications of opening up an HTTP/WS based
transport before doing so! Hackers on the internet are actively trying to subvert
MemeCore nodes with exposed APIs! Further, all browser tabs can access locally
running web servers, so malicious web pages could try to subvert locally available
APIs!**

### Operating a private network

Maintaining your own private network is more involved as a lot of configurations taken for
granted in the official networks need to be manually set up.

For gmeme nodes, you can set up private networks using PoSA consensus. Please refer to
the MemeCore documentation for detailed instructions on setting up validators and
system contracts.

## Contribution

Thank you for considering helping out with the source code! We welcome contributions
from anyone on the internet, and are grateful for even the smallest of fixes!

If you'd like to contribute to go-memecore, please fork, fix, commit and send a pull request
for the maintainers to review and merge into the main code base.

Please make sure your contributions adhere to our coding guidelines:

- Code must adhere to the official Go [formatting](https://golang.org/doc/effective_go.html#formatting)
  guidelines (i.e. uses [gofmt](https://golang.org/cmd/gofmt/)).
- Code must be documented adhering to the official Go [commentary](https://golang.org/doc/effective_go.html#commentary)
  guidelines.
- Pull requests need to be based on and opened against the `master` branch.
- Commit messages should be prefixed with the package(s) they modify.
  - E.g. "eth, rpc: make trace configs optional"

## License

Go MemeCore is based on [go-ethereum](https://github.com/ethereum/go-ethereum) and inherits its licensing terms.

The go-memecore/go-ethereum library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The go-memecore binaries (i.e. all code inside of the `cmd` directory) are licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
