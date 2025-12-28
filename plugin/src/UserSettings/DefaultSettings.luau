export type SettingType = "checkbox" | "dropdown" | "number"

local SettingType = {
	Checkbox = "checkbox" :: "checkbox",
	Dropdown = "dropdown" :: "dropdown",
	Number = "number" :: "number",
}

export type SettingGroup = "Telemetry"

local SettingGroup = {
	Telemetry = "Telemetry" :: "Telemetry",
}

export type SettingChoice = {
	description: string,
	displayName: string,
	name: string,
}

type BaseSetting = {
	name: string,
	group: SettingGroup,
	displayName: string,
	description: string,
	settingType: SettingType,
}

type CheckboxSetting = BaseSetting & {
	settingType: "checkbox",
	value: boolean,
}

type DropdownSetting = BaseSetting & {
	settingType: "dropdown",
	choices: { SettingChoice },
}

type NumberSetting = BaseSetting & {
	settingType: "number",
	range: NumberRange?,
	value: number,
}

export type Setting = CheckboxSetting | DropdownSetting | NumberSetting

local collectAnonymousUsageData: CheckboxSetting = {
	name = "collectAnonymousUsageData",
	group = SettingGroup.Telemetry,
	displayName = "Help improve Studio Rich Presence by sending anonymous usage data",
	description = "Allow Studio Rich Presence to collect anonymous usage data to help improve the product. No personal data is collected",
	settingType = SettingType.Checkbox,
	value = true,
}

local settings = {
	collectAnonymousUsageData = collectAnonymousUsageData,
}

export type Settings = typeof(settings)

return settings
