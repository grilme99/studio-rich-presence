--[[
	Dev Entry Point
	
	Starts a development session with Rojo serve.
]]

local process = require("@lune/process")

local cli = require("./lib/cli/parser")
local command = require("./commands/dev")

local function main()
	local parser = cli.parser()
	parser:setDescription(command.description)
	parser:setCommandName(`lune run {command.name}`)

	for _, arg: any in command.arguments do
		parser:add(arg.name, arg.kind, arg.options)
	end

	parser:parse(process.args)

	command.run({
		projectName = parser:get("project") :: string,
	})
end

main()
