package main

import (
	"github.com/vishnusomank/spire-k8s-keymanager/cmd"

	"github.com/accuknox/spire-plugin-sdk/pluginmain"
	keymanagerv1 "github.com/accuknox/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/accuknox/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	plugin := cmd.New(nil)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		keymanagerv1.KeyManagerPluginServer(plugin),
		// TODO: Remove if no configuration is required
		configv1.ConfigServiceServer(plugin),
	)
}
