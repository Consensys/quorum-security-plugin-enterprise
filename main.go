package main

import (
	"log"
	"os"

	"github.com/consensys/quorum-security-plugin-enterprise/internal"
	"github.com/hashicorp/go-plugin"
)

func main() {
	log.SetFlags(0)          // remove timestamp when logging to host process
	log.SetOutput(os.Stderr) // host process listens to stderr to log
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: internal.DefaultHandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"impl": &internal.SecurityPluginImpl{},
		},

		GRPCServer: plugin.DefaultGRPCServer,
	})
}
