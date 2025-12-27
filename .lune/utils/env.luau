--[[
	Environment Variable Utilities
	
	Loads environment variables from process environment or .env.luau file.
]]

local process = require("@lune/process")

local env = {}

local function loadEnvFile()
	local envFile = require("../../.env") :: any
	return envFile
end

--[[
	Loads an environment variable from the process environment or .env.luau file.
	
	@param name The environment variable name
	@return The environment variable value, or nil if not found
]]
local function loadEnvVar(name: string): string?
	local keyInEnv = process.env[name]
	if keyInEnv then
		return keyInEnv
	end

	local success, envFile = pcall(loadEnvFile)
	if not success then
		return nil
	end

	return envFile[name]
end
env.loadEnvVar = loadEnvVar

return env
