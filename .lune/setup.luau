--[[
	Setup Entry Point
	
	Sets up the project for development or CI.
]]

local process = require("@lune/process")

local cli = require("./lib/cli/parser")
local command = require("./commands/setup")

local function main()
	local parser = cli.parser()
	parser:setDescription(command.description)
	parser:setCommandName(`lune run {command.name}`)

	for _, arg: any in command.arguments do
		parser:add(arg.name, arg.kind, arg.options)
	end

	parser:parse(process.args)

	command.run({
		quiet = parser:has("quiet"),
	})
end

main()
