local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local Foundation = require(Packages.Foundation)
local React = require(Packages.React)
local ReactUtils = require(Packages.ReactUtils)

local useThemeName = require(script.Parent.useThemeName)

local FoundationProvider = Foundation.FoundationProvider

local e = React.createElement

type Props = {
	overlayGui: GuiBase2d?,
	children: React.ReactNode,
}

local function ContextProviders(props: Props)
	local themeName: useThemeName.ThemeName = useThemeName()

	return e(ReactUtils.ContextStack, {
		providers = {
			e(FoundationProvider, {
				theme = themeName,
				overlayGui = props.overlayGui,
			}),
		},
	}, props.children)
end

return ContextProviders
