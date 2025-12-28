local Plugin = script:FindFirstAncestor("StudioRichPresence")

local PluginLoader = require(script.Parent.PluginLoader)
local PluginLoaderBuilder = PluginLoader.PluginLoaderBuilder

export type PluginMain = (plugin: Plugin, pluginLoaderContext: PluginLoader.PluginLoaderContext) -> ()

local function setup(plugin: Plugin, main: PluginMain)
	plugin.Name = "StudioRichPresence"

	local buttonInfo = {
		-- Provide explicit type signature for lambda since the Luau typechecker can't infer this correctly.
		getName = function(getLocalizedText: (string, string) -> string): string
			return getLocalizedText("Plugin", "Name")
		end,
		getDescription = function(getLocalizedText: (string, string) -> string): string
			return getLocalizedText("Plugin", "Description")
		end,
		icon = "",
		enabled = false,
		clickableWhenViewportHidden = true,
	}

	local args: PluginLoader.Args = {
		plugin = plugin,
		pluginName = "StudioRichPresence",
		translationResourceTable = Plugin.Resources.LocalizedStrings,
		getToolbarName = function(getLocalizedText)
			return getLocalizedText("Plugin", "ToolbarName")
		end,
		buttonInfo = buttonInfo,
	}

	buttonInfo.enabled = true
	args.dockWidgetInfo = {
		id = "StudioRichPresence",
		name = "StudioRichPresence",
		dockWidgetPluginGuiInfo = DockWidgetPluginGuiInfo.new(
			Enum.InitialDockState.Right, --initialDockState,
			false, --initialEnabled,
			false, --initialEnabledShouldOverrideRestore,
			640, --size.X,
			480, --size.Y,
			250, --minSize.X,
			200 --minSize.Y
		),
		getDockTitle = function(getLocalizedText)
			return getLocalizedText("Plugin", "Name")
		end,
		zIndexBehavior = Enum.ZIndexBehavior.Sibling,
	}

	local pluginLoaderContext: any = PluginLoaderBuilder.build(args)
	local success = pluginLoaderContext.pluginLoader:waitForUserInteraction()
	if not success then
		-- Plugin destroyed
		return
	end

	main(plugin, pluginLoaderContext)
end

return setup
