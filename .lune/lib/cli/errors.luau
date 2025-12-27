--[[
	Error Handling Utilities
	
	Provides standardized error handling and reporting for CLI commands.
]]

local color = require("../../utils/color")
local process = require("@lune/process")

--[[
	Reports a validation error and exits.
	
	@param message The error message
	@param code Optional exit code (default: 1)
]]
local function validationError(message: string, code: number?)
	print(color.bold(color.red("Error: " .. message)))
	process.exit(code or 1)
end

--[[
	Reports a process execution error and exits.
	
	@param message The error message
	@param exitCode The process exit code
	@param stderr Optional stderr output
]]
local function processError(message: string, exitCode: number, stderr: string?)
	print(color.bold(color.red(message)))
	if stderr then
		print(stderr)
	end
	process.exit(exitCode)
end

--[[
	Reports a general error and exits.
	
	@param message The error message
	@param code Optional exit code (default: 1)
]]
local function error(message: string, code: number?)
	print(color.bold(color.red("Error: " .. message)))
	process.exit(code or 1)
end

return {
	validationError = validationError,
	processError = processError,
	error = error,
}
