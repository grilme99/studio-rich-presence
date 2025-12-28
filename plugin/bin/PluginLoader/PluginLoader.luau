--!nonstrict

local StudioService = game:GetService("StudioService")

export type Args = {
	pluginName: string,
	translationResourceTable: LocalizationTable,
	overrideLocaleId: string?,
	localizationNamespace: string?,
	shouldImmediatelyOpen: (() -> boolean)?,
}

-- Implementation could look like
-- This wraps a preexisting Signal.lua
-- If you call `:Fire()` before anything's connected, we'll store the args you passed
-- So that upon first connection, we'll flush them out
-- Otherwise works like a normal signal
local FlushOnConnectSignal = {}
FlushOnConnectSignal.__index = FlushOnConnectSignal
function FlushOnConnectSignal.new()
	local self = {
		_signal = Instance.new("BindableEvent"),
		_handlers = {},
		_eventsToFlush = {},
		_connections = {},
	}
	setmetatable(self, FlushOnConnectSignal)
	return self
end

export type FlushOnConnectSignal = typeof(FlushOnConnectSignal.new(...))

function FlushOnConnectSignal.Fire(self: FlushOnConnectSignal, ...)
	if #self._handlers > 0 then
		-- Our internal signal has connections, so just treat it like normal
		self._signal:Fire(...)
	else
		-- No connections yet, so save for later
		table.insert(self._eventsToFlush, { ... })
	end
end

function FlushOnConnectSignal.Connect(self: FlushOnConnectSignal, callback)
	if #self._handlers == 0 then
		-- This is the first connection
		for _, args in self._eventsToFlush do
			task.spawn(function()
				-- Warning: This has no checking for if the listener is disconnected whilst resuming
				callback(unpack(args))
			end)
		end
		self._eventsToFlush = {}
	end
	local conn = self._signal.Event:Connect(callback)
	table.insert(self._handlers, callback)
	table.insert(self._connections, conn)
	return conn
end

function FlushOnConnectSignal.Destroy(self: FlushOnConnectSignal)
	self._handlers = {}
	self._eventsToFlush = {}
	for _, conn in self._connections do
		conn:Disconnect()
	end
	self._signal:Destroy()
end

local PluginLoader = {}
PluginLoader.__index = PluginLoader

local function getLocale(overrideLocaleId: string?): string
	if overrideLocaleId ~= nil then
		return overrideLocaleId
	else
		return StudioService["StudioLocaleId"]
	end
end

function PluginLoader.new(args: Args)
	local self = setmetatable({
		_connectedSignals = {},
		_buttonConnections = {},
		_widgetConnections = {},
		_userHasInteracted = false,
		_destroyed = false,
		_userInteractionSignal = Instance.new("BindableEvent"),

		_initArgs = args,
	}, PluginLoader)

	if self._initArgs.localizationNamespace == nil then
		self._initArgs.localizationNamespace = "Studio"
	end

	self._locale = getLocale(args.overrideLocaleId)
	self._translator = args.translationResourceTable:GetTranslator(self._locale)

	if args.shouldImmediatelyOpen and args.shouldImmediatelyOpen() then
		(self :: any):_onUserInteracted()
	end
	return self
end

export type PluginLoader = typeof(PluginLoader.new(...))

function PluginLoader.Destroy(self: PluginLoader)
	for _, value in pairs(self._connectedSignals) do
		value[1]:Disconnect()
	end
	for _, value in pairs(self._buttonConnections) do
		value[1]:Disconnect()
	end
	for _, value in pairs(self._widgetConnections) do
		value[1]:Disconnect()
	end

	self._destroyed = true
	-- If we're currently waiting for interaction, resume that thread but with the `_destroyed = true`
	self:_onUserInteracted()
	if self._userInteractionSignal then
		self._userInteractionSignal:Destroy()
		self._userInteractionSignal = nil :: any
	end
end

function PluginLoader.getPluginName(self: PluginLoader): string
	return self._initArgs.pluginName
end

function PluginLoader.getLocalizedText(self: PluginLoader, scope: string, key: string): string
	local stringKey = string.format("%s.%s", scope, key)

	local function getTranslation(translator: Translator?)
		if not translator then
			return false, nil
		end

		local success, result = pcall(function()
			return translator:FormatByKey(stringKey)
		end)
		return success, result
	end

	local success, translated = getTranslation(self._translator)
	if success then
		return translated
	end

	if success and not string.find(translated, "Key .* not found for locale") then
		warn(translated, debug.traceback())
	end

	return stringKey
end

function PluginLoader._onUserInteracted(self: PluginLoader)
	self._userHasInteracted = true
	self._userInteractionSignal:Fire()
end

function PluginLoader.registerButton(self: PluginLoader, button: PluginToolbarButton): FlushOnConnectSignal
	local signal = FlushOnConnectSignal.new()
	local con = button.Click:Connect(function()
		self:_onUserInteracted()
		signal:Fire()
	end)
	self._buttonConnections[button] = { con :: any, signal }
	return signal
end

function PluginLoader.registerWidget(
	self: PluginLoader,
	widget: PluginGui,
	button: PluginToolbarButton?
): FlushOnConnectSignal
	local signal = FlushOnConnectSignal.new()
	local con = widget:GetPropertyChangedSignal("Enabled"):Connect(function()
		if widget.Enabled then
			self:_onUserInteracted()
		end
		if button then
			button:SetActive(widget.Enabled)
		end
		signal:Fire()
	end)
	self._widgetConnections[widget] = { con :: any, signal }
	if widget.Enabled then
		-- If widget is already visible, then we need to show something in it
		-- So treat this as a user interaction
		self:_onUserInteracted()
	end
	if button then
		button:SetActive(widget.Enabled)
	end
	return signal
end

function PluginLoader.registerSignal(self: PluginLoader, signal: RBXScriptSignal): FlushOnConnectSignal
	local retSignal = FlushOnConnectSignal.new()
	local con = signal:Connect(function(...)
		self:_onUserInteracted()
		retSignal:Fire(...)
	end)
	self._connectedSignals[signal] = { con :: any, retSignal }
	return retSignal
end

function PluginLoader.waitForUserInteraction(self: PluginLoader)
	if not self._userHasInteracted then
		(self :: any)._userInteractionConnection = self._userInteractionSignal.Event:Wait()
	end
	return not self._destroyed
end

return PluginLoader
