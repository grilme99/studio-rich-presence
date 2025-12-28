local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local SignalsReact = require(Packages.SignalsReact)

local PluginStore = require(Plugin.Source.Plugin.PluginStore)

local function usePlugin(): Plugin
	local pluginStore = SignalsReact.useSignalState(PluginStore.get)
	local plugin = pluginStore.getPlugin()
	if plugin == nil then
		error("Plugin not found")
	end
	return plugin
end

return usePlugin
