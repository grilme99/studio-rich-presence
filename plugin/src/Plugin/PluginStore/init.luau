local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local Signals = require(Packages.Signals)

local createPluginStore = require(script.createPluginStore)

return {
	get = Signals.createComputed(createPluginStore),
}
