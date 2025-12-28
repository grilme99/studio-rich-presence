local HttpService = game:GetService("HttpService")

local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local Signals = require(Packages.Signals)

local Logger = require(Plugin.Source.Logger)
local PluginStore = require(script.Parent.PluginStore)

export type PluginSettingsStore<T> = {
	getStorage: Signals.getter<T>,
	setStorage: Signals.setter<T>,

	isSettingDefault: (settingName: string) -> boolean,

	getIsLoading: Signals.getter<boolean>,
	getErr: Signals.getter<string?>,

	dispose: () -> (),
}

--[[
	Creates a store to manage plugin settings.

	Settings are persisted using Plugin:SetSetting and Plugin:GetSetting, and
    are stored as JSON strings. The settings are loaded once when the store is
    first created, and any changes to the settings are automatically saved.
]]
local function createPluginSettingsStore<T>(
	storageKey: string,
	defaultValue: T,
	validate: (value: any) -> (boolean, string)
): PluginSettingsStore<T>
	local getStorage, setStorage = Signals.createSignal(defaultValue)
	local getIsLoading, setIsLoading = Signals.createSignal(true)
	local getErr, setErr = Signals.createSignal(nil :: string?)

	local function readPluginSettingsAsync(plugin: Plugin): T?
		Logger:Info(`reading plugin settings for {storageKey} from disk...`)

		local data = plugin:GetSetting(storageKey)

		Logger:Debug(`read raw plugin settings for {storageKey}:`, data)

		if typeof(data) == "string" then
			Logger:Info(`deserializing plugin settings for {storageKey} to object...`)

			local success, result = pcall(function()
				return HttpService:JSONDecode(data)
			end)

			if not success then
				Logger:Warn(`failed to load plugin settings for {storageKey}:`, result)
				setErr(result)
				return nil
			end

			local isValid, message = validate(result)

			if not isValid then
				Logger:Warn(`plugin settings are malformed for {storageKey}:`, message)
				setErr(message)
				return nil
			end

			Logger:Info(`got plugin settings for {storageKey}:`, result)

			return result
		end

		Logger:Info("no plugin settings to read")

		return nil
	end

	local function writePluginSettingsAsync(plugin: Plugin, storage: T)
		Logger:Info("writing plugin settings to disk...")
		local data = HttpService:JSONEncode(storage)

		if data then
			local success, err = pcall(function()
				plugin:SetSetting(storageKey, data)
			end)

			if success then
				Logger:Info(`wrote plugin settings to disk: {data}`)
			else
				Logger:Warn(`failed to write plugin settings to disk: {err}`)
			end
		end
	end

	local prevStorage: T?
	local dispose = Signals.createEffect(function(scope)
		local storage = getStorage(scope)
		local plugin = PluginStore.get(scope).getPlugin(scope)

		if plugin then
			if getIsLoading(false) then
				task.spawn(function()
					local data = readPluginSettingsAsync(plugin)
					if data then
						setStorage(data)
					end
					Logger:Debug("finished loading plugin settings")
					setIsLoading(false)
				end)
			end

			if storage ~= prevStorage then
				task.spawn(function()
					writePluginSettingsAsync(plugin, storage)
				end)
			end
		end

		prevStorage = storage
	end)

	local function isSettingDefault(settingName: string): boolean
		local storage = getStorage(false)
		if typeof(defaultValue) ~= "table" or typeof(storage) ~= "table" then
			return true
		end

		local settingDefaultValue = defaultValue[settingName]
		local storedValue = storage[settingName]

		return storedValue == nil or storedValue == settingDefaultValue
	end

	return {
		getIsLoading = getIsLoading,
		getErr = getErr,
		getStorage = getStorage,
		setStorage = setStorage,
		isSettingDefault = isSettingDefault,
		dispose = dispose,
	}
end

return createPluginSettingsStore
