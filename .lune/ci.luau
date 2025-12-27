--[[
	CI Entry Point
	
	Runs static analysis checks for continuous integration.
]]

local process = require("@lune/process")

local cli = require("./lib/cli/parser")
local command = require("./commands/ci")

local function main()
	local parser = cli.parser()
	parser:setDescription(command.description)
	parser:setCommandName(`lune run {command.name}`)

	for _, arg: any in command.arguments do
		parser:add(arg.name, arg.kind, arg.options)
	end

	parser:parse(process.args)

	command.run({
		fix = parser:has("fix"),
	})
end

main()
