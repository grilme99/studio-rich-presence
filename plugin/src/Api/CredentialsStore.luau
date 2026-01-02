--[[
	Store for persisting API credentials (auth token and client key).

	Credentials are stored encrypted in plugin settings and are required
	for all authenticated API calls.
]]

local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local Signals = require(Packages.Signals)
local t = require(Packages.t)

local createPluginSettingsStore = require(Plugin.Source.Plugin.createPluginSettingsStore)

export type Credentials = {
	authToken: string?,
	clientKey: string?,
}

local defaultValue: Credentials = {
	authToken = nil,
	clientKey = nil,
}

local validate = t.interface({
	authToken = t.optional(t.string),
	clientKey = t.optional(t.string),
})

return {
	get = Signals.createComputed(function(_scope)
		return createPluginSettingsStore("PresenceApiCredentials", defaultValue, validate)
	end),
}
