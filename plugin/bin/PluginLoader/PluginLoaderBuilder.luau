local PluginLoader = require(script.Parent.PluginLoader)

export type GetLocalizedTextFunc = ((string, string) -> string) -> string

export type ButtonInfo = {
	getName: GetLocalizedTextFunc,
	getDescription: GetLocalizedTextFunc,
	icon: string?,
	text: (string | GetLocalizedTextFunc)?, -- We can instead change this to getText with type GetLocalizedTextFunc, but this requires refactoring other plugins
	clickableWhenViewportHidden: boolean?,
	enabled: boolean?,
}

export type DockWidgetInfo = {
	dockWidgetPluginGuiInfo: DockWidgetPluginGuiInfo,
	getDockTitle: GetLocalizedTextFunc,
	id: string,
	name: (string | GetLocalizedTextFunc)?,
	zIndexBehavior: Enum.ZIndexBehavior,
}

export type Args = {
	plugin: Plugin,
	pluginName: string,
	translationResourceTable: LocalizationTable,
	overrideLocaleId: string?,
	localizationNamespace: string?,
	noToolbar: boolean?,
	getToolbarName: GetLocalizedTextFunc?,
	buttonInfo: ButtonInfo?,
	dockWidgetInfo: DockWidgetInfo?,
	extraTriggers: { [string]: () -> RBXScriptSignal | { Connect: (any) -> any } }?,
	shouldImmediatelyOpen: (() -> boolean)?,
}

export type PluginLoaderContext = {
	pluginLoader: PluginLoader.PluginLoader,
	plugin: Plugin,
	toolbar: PluginToolbar?,
	mainButton: PluginToolbarButton?,
	mainDockWidget: PluginGui?,
	mainButtonClickedSignal: PluginLoader.FlushOnConnectSignal,
	signals: {
		[string]: PluginLoader.FlushOnConnectSignal,
	},
}

local PluginLoaderBuilder = {}

local function createDockWidgetPluginGui(
	plugin: Plugin,
	dockWidgetInfo: DockWidgetInfo,
	title: string,
	name: string?
): DockWidgetPluginGui
	local id = dockWidgetInfo.id
	local newDockWidget = plugin:CreateDockWidgetPluginGuiAsync(id, dockWidgetInfo.dockWidgetPluginGuiInfo)
	newDockWidget.Title = title
	if name ~= nil then
		newDockWidget.Name = name
	end
	newDockWidget.ZIndexBehavior = dockWidgetInfo.zIndexBehavior or Enum.ZIndexBehavior.Sibling
	return newDockWidget
end

function PluginLoaderBuilder.build(args: Args)
	local pluginLoaderArgs: PluginLoader.Args = {
		plugin = args.plugin,
		pluginName = args.pluginName,
		translationResourceTable = args.translationResourceTable,
		overrideLocaleId = args.overrideLocaleId,
		localizationNamespace = args.localizationNamespace,
		shouldImmediatelyOpen = args.shouldImmediatelyOpen,
	}

	local pluginLoader = PluginLoader.new(pluginLoaderArgs)

	local getLocalizedText = function(...)
		return pluginLoader:getLocalizedText(...)
	end

	local toolbar
	local mainButton
	local mainButtonClickedSignal
	if args.noToolbar ~= true then
		local toolbarString = args.getToolbarName and args.getToolbarName(getLocalizedText)
		toolbar = args.plugin:CreateToolbar(toolbarString :: any)

		local buttonInfo = args.buttonInfo :: any
		mainButton = toolbar:CreateButton(
			buttonInfo.getName(getLocalizedText),
			buttonInfo.getDescription(getLocalizedText),
			buttonInfo.icon,
			if type(buttonInfo.text) == "function" then buttonInfo.text(getLocalizedText) else buttonInfo.text
		)
		if buttonInfo.clickableWhenViewportHidden then
			mainButton.ClickableWhenViewportHidden = buttonInfo.clickableWhenViewportHidden
		end
		if buttonInfo.enabled ~= nil then
			mainButton.Enabled = buttonInfo.enabled
		end

		mainButtonClickedSignal = pluginLoader:registerButton(mainButton)
	end

	local mainDockWidget = nil
	local dockWidgetInfo = args.dockWidgetInfo
	if dockWidgetInfo then
		local dockTitleString = dockWidgetInfo.getDockTitle(getLocalizedText)

		if dockWidgetInfo.name then
			local dockWidgetName = if type(dockWidgetInfo.name) == "function"
				then dockWidgetInfo.name(getLocalizedText)
				else dockWidgetInfo.name
			mainDockWidget = createDockWidgetPluginGui(args.plugin, dockWidgetInfo, dockTitleString, dockWidgetName)
		else
			mainDockWidget = createDockWidgetPluginGui(args.plugin, dockWidgetInfo, dockTitleString)
		end

		pluginLoader:registerWidget(mainDockWidget, mainButton)
	end

	local signals = {}

	if args.extraTriggers then
		for name, signalGetter in pairs(args.extraTriggers) do
			local signal = signalGetter()
			signals[name] = pluginLoader:registerSignal(signal :: any)
		end
	end

	local pluginLoaderContext: PluginLoaderContext = {
		pluginLoader = pluginLoader,
		plugin = args.plugin,
		toolbar = toolbar,
		mainButton = mainButton,
		mainDockWidget = mainDockWidget,
		mainButtonClickedSignal = mainButtonClickedSignal,
		signals = signals,
	}

	args.plugin.Unloading:Connect(function()
		pluginLoader:Destroy()
		pluginLoader = nil :: any
		pluginLoaderContext.pluginLoader = nil :: any
		if pluginLoaderContext.mainButtonClickedSignal then
			(pluginLoaderContext.mainButtonClickedSignal :: any):Destroy()
		end
		for _, signal in pairs(pluginLoaderContext.signals) do
			(signal :: any):Destroy()
		end
	end)

	return pluginLoaderContext
end

return PluginLoaderBuilder
