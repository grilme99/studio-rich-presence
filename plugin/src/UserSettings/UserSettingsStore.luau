local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local Signals = require(Packages.Signals)
local t = require(Packages.t)

local createPluginSettingsStore = require(Plugin.Source.Plugin.createPluginSettingsStore)
local defaultSettings = require(script.Parent.DefaultSettings)

export type UserSettings = {
	collectAnonymousUsageData: boolean,
}

local defaultValue: UserSettings = {
	collectAnonymousUsageData = defaultSettings.collectAnonymousUsageData.value,
}

local validate = t.interface({
	collectAnonymousUsageData = t.boolean,
})

-- defaultValue needs to be kept in sync with the keys in defaultSettings
for key in defaultSettings do
	assert(defaultValue[key] ~= nil, "setting with key {key} is missing from UserSettingsStore")
end

return {
	get = Signals.createComputed(function(_scope)
		return createPluginSettingsStore("PresenceUserSettings", defaultValue, validate)
	end),
}
