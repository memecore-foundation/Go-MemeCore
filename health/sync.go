package health

import (
	"net/http"

	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
)

type handler struct {
	eth *eth.Ethereum
}

// return 200 if node is synced for rpc service, or return 503.
func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.eth.Synced() {
		w.WriteHeader(200)
	} else {
		w.WriteHeader(503)
	}
}

func NewHandler(eth *eth.Ethereum, cors, vhosts []string) http.Handler {
	handler := node.NewHTTPHandlerStack(handler{eth}, cors, vhosts, nil)
	return handler
}
