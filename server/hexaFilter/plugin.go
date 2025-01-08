package hexaFilter

import (
	"fmt"

	"github.com/hexa-org/policy-opa/server/conditionEvaluator"
	"github.com/open-policy-agent/opa/plugins"
	"golang.org/x/net/context"

	"sync"
)

const PluginName = "hexaFilter"

type Config struct {
	// reserved for future use
}

type HexaFilter struct {
	manager *plugins.Manager
	mtx     sync.Mutex
	config  Config
}

func (h *HexaFilter) Start(_ context.Context) error {
	h.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})
	fmt.Println("HexaFilter plugin started")
	return nil
}

func (h *HexaFilter) Stop(_ context.Context) {
	h.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
	fmt.Println("HexaFilter plugin STOPPED")
}

func (h *HexaFilter) Reconfigure(_ context.Context, config interface{}) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	h.config = config.(Config)
}

func (h *HexaFilter) Evaluate(input string, expression string) (bool, error) {
	return conditionEvaluator.Evaluate(expression, input)
}
