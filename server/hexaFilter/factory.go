package hexaFilter

import (
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/util"
)

type Factory struct{}

func (Factory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	return &HexaFilter{manager: m, config: config.(Config)}
}

func (Factory) Validate(_ *plugins.Manager, config []byte) (interface{}, error) {
	parsedConfig := Config{}
	err := util.Unmarshal(config, &parsedConfig)
	return parsedConfig, err
}
