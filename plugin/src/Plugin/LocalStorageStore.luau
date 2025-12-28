local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local Signals = require(Packages.Signals)
local t = require(Packages.t)

local createPluginSettingsStore = require(script.Parent.createPluginSettingsStore)

export type LocalStorageStore = {
	wasUserPromptedForTelemetry: boolean,
}

local defaultValue: LocalStorageStore = {
	wasUserPromptedForTelemetry = false,
}

local validate = t.interface({
	wasUserPromptedForTelemetry = t.boolean,
})

return {
	get = Signals.createComputed(function(_scope)
		return createPluginSettingsStore("PresenceLocalStorage", defaultValue, validate)
	end),
}
