// Package plasmactlprocessors provides common launchr processors for actions.
package plasmactlprocessors

import (
	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
)

func init() {
	launchr.RegisterPlugin(Plugin{})
}

// Plugin is [launchr.Plugin] to provide action processors.
type Plugin struct{}

// PluginInfo implements [launchr.Plugin] interface.
func (p Plugin) PluginInfo() launchr.PluginInfo {
	return launchr.PluginInfo{}
}

// OnAppInit implements [launchr.OnAppInitPlugin] interface.
func (p Plugin) OnAppInit(app launchr.App) error {
	// Get services.
	var tp *action.TemplateProcessors
	var k keyring.Keyring
	app.Services().Get(&tp)
	app.Services().Get(&k)
	addTemplateProcessors(tp, k)
	return nil
}

func addTemplateProcessors(tp *action.TemplateProcessors, k keyring.Keyring) {
	tp.AddTemplateFunc("AnsibleVault", func(ctx action.TemplateFuncContext) any {
		ansVault := &ansibleVaultTemplateFunc{keyring: k, action: ctx.Action()}
		return ansVault.Get
	})
}
