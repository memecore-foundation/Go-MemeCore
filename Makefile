# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: geth android ios evm all test clean privnet_nodes_stop privnet_bootnode_stop privnet_stop privnet_clean privnet_start privnet_start_four privnet_start_seven

GETHBIN = ./build/bin
GO ?= latest
GORUN = go run

MAIN_DIR = ./privnet
SINGLE_DIR = $(MAIN_DIR)/single
FOUR_DIR = $(MAIN_DIR)/four
SEVEN_DIR = $(MAIN_DIR)/seven

NODE1 = node1
NODE1_PORT = 30306
NODE1_AUTH_PORT = 8552
NODE1_HTTP_PORT = 8562
NODE1_WS_PORT = 8572

NODE2 = node2
NODE2_PORT = 30307
NODE2_AUTH_PORT = 8553
NODE2_HTTP_PORT = 8563
NODE2_WS_PORT = 8573

NODE3 = node3
NODE3_PORT = 30308
NODE3_AUTH_PORT = 8554
NODE3_HTTP_PORT = 8564
NODE3_WS_PORT = 8574

NODE4 = node4
NODE4_PORT = 30309
NODE4_AUTH_PORT = 8555
NODE4_HTTP_PORT = 8565
NODE4_WS_PORT = 8575

NODE5 = node5
NODE5_PORT = 30310
NODE5_AUTH_PORT = 8556
NODE5_HTTP_PORT = 8566
NODE5_WS_PORT = 8576

NODE6 = node6
NODE6_PORT = 30311
NODE6_AUTH_PORT = 8557
NODE6_HTTP_PORT = 8567
NODE6_WS_PORT = 8577

NODE7 = node7
NODE7_PORT = 30312
NODE7_AUTH_PORT = 8558
NODE7_HTTP_PORT = 8568
NODE7_WS_PORT = 8578

NODE8 = node8
NODE8_PORT = 30313
NODE8_AUTH_PORT = 8559
NODE8_HTTP_PORT = 8569
NODE8_WS_PORT = 8579

PASSWORD_LEN = 32
GENESIS_WORK_JSON = genesis_privnet.json

BOOTNODE = bootnode
BOOTNODE_PORT = 30305
BOOTNODE_LOGLEVEL = 5

RESTRICTED_NETWORK = 127.0.0.0/24
NAT_POLICY = none

define run_bootnode
    @$(GETHBIN)/bootnode -nodekey $(1)/$(BOOTNODE)/bootnode.key \
    	-addr :$(BOOTNODE_PORT) \
    	-verbosity $(BOOTNODE_LOGLEVEL) > $(1)/$(BOOTNODE)/bootnode.log 2>&1 &
endef

define run_miner_node
	$(call run_node,$(1),$(2),$(3),$(4),$(5),$(6),--mine --miner.etherbase="0x$$(cat $(1)/$(7)/node_address.txt)")
endef

define run_node
	@$(GETHBIN)/geth --datadir $(1)/$(2) \
		--port $(3) \
		--bootnodes "enode://$$(cat $(1)/$(BOOTNODE)/bootnode_address.txt)@127.0.0.1:0?discport=$(BOOTNODE_PORT)" \
		--networkid "$$(cat $(1)/networkid.txt)" \
		--unlock 0x"$$(cat $(1)/$(2)/node_address.txt)" \
		--authrpc.port $(4) \
		--http \
		--http.port $(5) \
		--http.addr 0.0.0.0 \
		--http.vhosts "*" \
		--ws \
		--ws.addr 0.0.0.0 \
		--ws.port $(6) \
		--allow-insecure-unlock \
		--password $(1)/$(2)/password.txt \
		--metrics \
		--nat $(NAT_POLICY) \
		--netrestrict $(RESTRICTED_NETWORK) \
		$(7) >  $(1)/$(2)/geth_node.log 2>&1 &
endef

define init_node
    @$(GETHBIN)/geth init --datadir $(1)/$(2) $(1)/$(GENESIS_WORK_JSON) > $(1)/$(2)/geth_init.log 2>&1
endef

geth:
	$(GORUN) build/ci.go install ./cmd/geth
	@echo "Done building."
	@echo "Run \"$(GETHBIN)/geth\" to launch geth."

all:
	$(GORUN) build/ci.go install

test: all
	$(GORUN) build/ci.go test

lint: ## Run linters.
	$(GORUN) build/ci.go lint

clean:
	go clean -cache
	rm -fr build/_workspace/pkg/ $(GETHBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go install golang.org/x/tools/cmd/stringer@latest
	env GOBIN= go install github.com/fjl/gencodec@latest
	env GOBIN= go install github.com/golang/protobuf/protoc-gen-go@latest
	env GOBIN= go install ./cmd/abigen
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Privnet targets

privnet_nodes_stop:
	@echo "Killing nodes processes"
	@killall -w -v -INT geth || :

privnet_bootnode_stop:
	@echo "Killing bootnode processes"
	@killall -w -v -9 bootnode || :

privnet_stop: privnet_bootnode_stop privnet_nodes_stop

privnet_clean: privnet_stop
	@echo "Cleaning the nodes database files from $(MAIN_DIR)"
	@find $(MAIN_DIR)/* -type d -name 'geth' -print -exec rm -rf {} +
	@find $(MAIN_DIR)/* -type s,f -not \( -path '*/keystore/*' -or -name '*.json' -or -name '*.txt' -or -name '*.key' -or -name '*.md' \) -print -exec rm -f {} +

$(SINGLE_DIR)/$(NODE1)/geth:
	@echo "Initializing $(NODE1) from genesis"
	$(call init_node,$(SINGLE_DIR),$(NODE1))

$(SINGLE_DIR)/$(NODE2)/geth:
	@echo "Initializing $(NODE2) from genesis"
	$(call init_node,$(SINGLE_DIR),$(NODE2))

$(FOUR_DIR)/$(NODE1)/geth:
	@echo "Initializing $(NODE1) from genesis"
	$(call init_node,$(FOUR_DIR),$(NODE1))

$(FOUR_DIR)/$(NODE2)/geth:
	@echo "Initializing $(NODE2) from genesis"
	$(call init_node,$(FOUR_DIR),$(NODE2))

$(FOUR_DIR)/$(NODE3)/geth:
	@echo "Initializing $(NODE3) from genesis"
	$(call init_node,$(FOUR_DIR),$(NODE3))

$(FOUR_DIR)/$(NODE4)/geth:
	@echo "Initializing $(NODE4) from genesis"
	$(call init_node,$(FOUR_DIR),$(NODE4))

$(FOUR_DIR)/$(NODE5)/geth:
	@echo "Initializing $(NODE5) from genesis"
	$(call init_node,$(FOUR_DIR),$(NODE5))

$(SEVEN_DIR)/$(NODE1)/geth:
	@echo "Initializing $(NODE1) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE1))

$(SEVEN_DIR)/$(NODE2)/geth:
	@echo "Initializing $(NODE2) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE2))

$(SEVEN_DIR)/$(NODE3)/geth:
	@echo "Initializing $(NODE3) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE3))

$(SEVEN_DIR)/$(NODE4)/geth:
	@echo "Initializing $(NODE4) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE4))

$(SEVEN_DIR)/$(NODE5)/geth:
	@echo "Initializing $(NODE5) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE5))

$(SEVEN_DIR)/$(NODE6)/geth:
	@echo "Initializing $(NODE6) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE6))

$(SEVEN_DIR)/$(NODE7)/geth:
	@echo "Initializing $(NODE7) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE7))

$(SEVEN_DIR)/$(NODE8)/geth:
	@echo "Initializing $(NODE8) from genesis"
	$(call init_node,$(SEVEN_DIR),$(NODE8))

privnet_start: $(SINGLE_DIR)/$(NODE1)/geth $(SINGLE_DIR)/$(NODE2)/geth
	@echo "Starting nodes..."
	$(call run_bootnode,$(SINGLE_DIR))
	$(call run_miner_node,$(SINGLE_DIR),$(NODE1),$(NODE1_PORT),$(NODE1_AUTH_PORT),$(NODE1_HTTP_PORT),$(NODE1_WS_PORT),$(NODE1))
	$(call run_node,$(SINGLE_DIR),$(NODE2),$(NODE2_PORT),$(NODE2_AUTH_PORT),$(NODE2_HTTP_PORT),$(NODE2_WS_PORT))
	@echo "OK! Check logs in $(SINGLE_DIR)/<node_dir>/geth_node.log"

privnet_start_four: $(FOUR_DIR)/$(NODE1)/geth $(FOUR_DIR)/$(NODE2)/geth $(FOUR_DIR)/$(NODE3)/geth $(FOUR_DIR)/$(NODE4)/geth $(FOUR_DIR)/$(NODE5)/geth
	@echo "Starting nodes..."
	$(call run_bootnode,$(FOUR_DIR))
	$(call run_miner_node,$(FOUR_DIR),$(NODE1),$(NODE1_PORT),$(NODE1_AUTH_PORT),$(NODE1_HTTP_PORT),$(NODE1_WS_PORT),$(NODE1))
	$(call run_miner_node,$(FOUR_DIR),$(NODE2),$(NODE2_PORT),$(NODE2_AUTH_PORT),$(NODE2_HTTP_PORT),$(NODE2_WS_PORT),$(NODE2))
	$(call run_miner_node,$(FOUR_DIR),$(NODE3),$(NODE3_PORT),$(NODE3_AUTH_PORT),$(NODE3_HTTP_PORT),$(NODE3_WS_PORT),$(NODE3))
	$(call run_miner_node,$(FOUR_DIR),$(NODE4),$(NODE4_PORT),$(NODE4_AUTH_PORT),$(NODE4_HTTP_PORT),$(NODE4_WS_PORT),$(NODE4))
	$(call run_node,$(FOUR_DIR),$(NODE5),$(NODE5_PORT),$(NODE5_AUTH_PORT),$(NODE5_HTTP_PORT),$(NODE5_WS_PORT))
	@echo "OK! Check logs in $(FOUR_DIR)/<node_dir>/geth_node.log"

privnet_start_seven: $(SEVEN_DIR)/$(NODE1)/geth $(SEVEN_DIR)/$(NODE2)/geth $(SEVEN_DIR)/$(NODE3)/geth $(SEVEN_DIR)/$(NODE4)/geth $(SEVEN_DIR)/$(NODE5)/geth $(SEVEN_DIR)/$(NODE6)/geth $(SEVEN_DIR)/$(NODE7)/geth $(SEVEN_DIR)/$(NODE8)/geth
	@echo "Starting nodes..."
	$(call run_bootnode,$(SEVEN_DIR))
	$(call run_miner_node,$(SEVEN_DIR),$(NODE1),$(NODE1_PORT),$(NODE1_AUTH_PORT),$(NODE1_HTTP_PORT),$(NODE1_WS_PORT),$(NODE1))
	$(call run_miner_node,$(SEVEN_DIR),$(NODE2),$(NODE2_PORT),$(NODE2_AUTH_PORT),$(NODE2_HTTP_PORT),$(NODE2_WS_PORT),$(NODE2))
	$(call run_miner_node,$(SEVEN_DIR),$(NODE3),$(NODE3_PORT),$(NODE3_AUTH_PORT),$(NODE3_HTTP_PORT),$(NODE3_WS_PORT),$(NODE3))
	$(call run_miner_node,$(SEVEN_DIR),$(NODE4),$(NODE4_PORT),$(NODE4_AUTH_PORT),$(NODE4_HTTP_PORT),$(NODE4_WS_PORT),$(NODE4))
	$(call run_miner_node,$(SEVEN_DIR),$(NODE5),$(NODE5_PORT),$(NODE5_AUTH_PORT),$(NODE5_HTTP_PORT),$(NODE5_WS_PORT),$(NODE5))
	$(call run_miner_node,$(SEVEN_DIR),$(NODE6),$(NODE6_PORT),$(NODE6_AUTH_PORT),$(NODE6_HTTP_PORT),$(NODE6_WS_PORT),$(NODE6))
	$(call run_miner_node,$(SEVEN_DIR),$(NODE7),$(NODE7_PORT),$(NODE7_AUTH_PORT),$(NODE7_HTTP_PORT),$(NODE7_WS_PORT),$(NODE7))
	$(call run_node,$(SEVEN_DIR),$(NODE8),$(NODE8_PORT),$(NODE8_AUTH_PORT),$(NODE8_HTTP_PORT),$(NODE8_WS_PORT))
	@echo "OK! Check logs in $(SEVEN_DIR)/<node_dir>/geth_node.log"