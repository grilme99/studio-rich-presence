--[[
	CLI Argument Parser
	
	Adapted from lute's CLI parser for Lune runtime.
	Source: https://github.com/luau-lang/lute/blob/8696479e2ef59e53454d98aaebeabc61ebd902b5/batteries/cli.luau
	MIT License - Copyright (c) 2024–2025 Roblox Corporation
	
	Provides a flexible command-line argument parser with support for:
	- Positional arguments
	- Flags (--flag, -f)
	- Options (--key=value, -k=value)
	- Aliases
	- Required/optional arguments
	- Default values
	- Help generation
	- Forwarded arguments (--)
	- Universal --help/-h flag
]]

local errors = require("./errors")
local process = require("@lune/process")

local cli = {}
cli.__index = cli

type ArgKind = "positional" | "flag" | "option"
type ArgOptions = {
	help: string?,
	aliases: { string }?,
	default: string?,
	required: boolean?,
}

type ArgData = {
	name: string,
	kind: ArgKind,
	options: ArgOptions,
}

type ParseResult = {
	values: { [string]: string },
	flags: { [string]: boolean },
	fwdArgs: { string },
}

type ParserData = {
	arguments: { [number]: ArgData },
	positional: { [number]: ArgData },
	parsed: ParseResult,
	description: string?,
	commandName: string?,
}

type ParserInterface = typeof(cli)
export type Parser = typeof(setmetatable({} :: ParserData, {} :: ParserInterface))

--[[
	Creates a new CLI parser instance.
	
	@return A new parser instance
]]
function cli.parser(): Parser
	local self = {
		arguments = {},
		positional = {},
		parsed = { values = {}, flags = {}, fwdArgs = {} },
		description = nil,
		commandName = nil,
	}

	return setmetatable(self, cli)
end

--[[
	Sets the command description.
	
	@param description The command description
]]
function cli.setDescription(self: Parser, description: string): ()
	self.description = description
end

--[[
	Sets the command name (for usage display).
	
	@param name The command name
]]
function cli.setCommandName(self: Parser, name: string): ()
	self.commandName = name
end

--[[
	Adds an argument definition to the parser.
	
	@param name The argument name
	@param kind The argument kind (positional, flag, or option)
	@param options Optional configuration (help, aliases, default, required)
]]
function cli.add(self: Parser, name: string, kind: ArgKind, options: ArgOptions?): ()
	local argument = {
		name = name,
		kind = kind,
		options = options or { aliases = {}, required = false },
	}

	table.insert(self.arguments, argument)
	if kind == "positional" then
		table.insert(self.positional, argument)
	end
end

--[[
	Checks if --help or -h is present in arguments and shows help if so.
	
	@param args The arguments to check
	@return True if help was shown, false otherwise
]]
function cli.checkHelp(self: Parser, args: { string }): boolean
	for _, arg in args do
		if arg == "--help" or arg == "-h" then
			self:help()
			return true
		end
	end
	return false
end

--[[
	Parses command-line arguments.
	
	@param args The arguments to parse (typically from process.args)
]]
function cli.parse(self: Parser, args: { string }): ()
	-- Check for help flag first
	if self:checkHelp(args) then
		process.exit(0)
	end

	local i = 0
	local pos_index = 1

	while i < #args do
		i += 1

		local arg = args[i]

		-- if the argument is exactly "--", we pass everything along
		if arg == "--" then
			table.move(args, i + 1, #args, 1, self.parsed.fwdArgs)
			break
		end

		-- if the argument starts with two dashes, we're parsing either a flag or an option
		if string.sub(arg, 1, 2) == "--" then
			local name = string.sub(arg, 3)
			local found = false

			for _, argument in self.arguments do
				local aliases = argument.options.aliases or {}

				if argument.name == name or table.find(aliases, name) then
					found = true

					if argument.kind == "option" then
						-- advance past the argument
						i += 1

						if i > #args then
							errors.error(`Missing value for argument: {argument.name}`)
						end
						self.parsed.values[argument.name] = args[i]

						break
					end

					self.parsed.flags[argument.name] = true
					break
				end
			end

			if not found then
				errors.error(`Unknown argument: {name}`)
			end
			continue
		end

		-- if the argument starts with a single dash, we're parsing a flag
		if string.sub(arg, 1, 1) == "-" then
			local flags = string.sub(arg, 2)

			for j = 1, #flags do
				local name = string.sub(flags, j, j)
				local found = false
				for _, argument in self.arguments do
					local aliases = argument.options.aliases or {}
					if argument.name == name or table.find(aliases, name) then
						found = true
						if argument.kind == "option" then
							i += 1
							if i > #args then
								errors.error(`Missing value for argument: {argument.name}`)
							end
							self.parsed.values[argument.name] = args[i]
						else
							self.parsed.flags[argument.name] = true
						end
						break
					end
				end

				if not found then
					errors.error(`Unknown argument: {name}`)
				end
			end

			continue
		end

		-- if we have positional arguments left, we can take this argument as one
		if pos_index <= #self.positional then
			self.parsed.values[self.positional[pos_index].name] = arg
			pos_index += 1
			continue
		end

		-- otherwise, the argument is forwarded on
		table.insert(self.parsed.fwdArgs, arg)
	end

	-- check that all required arguments are present, and set any default values as needed
	for _, argument in self.arguments do
		if argument.options.required and self.parsed.values[argument.name] == nil then
			errors.error(`Missing required argument: {argument.name}`)
		end

		if self.parsed.values[argument.name] == nil and argument.options.default then
			self.parsed.values[argument.name] = argument.options.default
		end
	end
end

--[[
	Gets the value of a positional argument or option.
	
	@param name The argument name
	@return The argument value, or nil if not set
]]
function cli.get(self: Parser, name: string): string?
	return self.parsed.values[name]
end

--[[
	Checks if a flag is present.
	
	@param name The flag name
	@return True if the flag is present, false otherwise
]]
function cli.has(self: Parser, name: string): boolean
	return self.parsed.flags[name] ~= nil
end

--[[
	Gets forwarded arguments (arguments after --).
	
	@return The forwarded arguments, or nil if none
]]
function cli.forwarded(self: Parser): { string }?
	return self.parsed.fwdArgs
end

--[[
	Prints help information for all defined arguments.
]]
function cli.help(self: Parser): ()
	-- Print description if set
	if self.description then
		print(self.description)
		print()
	end

	-- Build usage line
	local usageParts: { string } = {}
	if self.commandName then
		table.insert(usageParts, self.commandName)
	end

	-- Add positional arguments to usage
	for _, arg in self.positional do
		if arg.options.required then
			table.insert(usageParts, `<{arg.name}>`)
		else
			table.insert(usageParts, `[{arg.name}]`)
		end
	end

	-- Add options indicator if there are any flags/options
	local hasOptions = false
	for _, arg in self.arguments do
		if arg.kind ~= "positional" then
			hasOptions = true
			break
		end
	end

	if hasOptions then
		table.insert(usageParts, "[OPTIONS]")
	end

	local usageLine = table.concat(usageParts, " ")
	print(`Usage: {usageLine}`)
	print()

	-- Print Arguments section if there are positional arguments
	if #self.positional > 0 then
		print("Arguments:")
		for _, argument in self.positional do
			local reqStr = if argument.options.required then "" else "(optional) "
			local helpText = argument.options.help or ""
			print(string.format("  <%s>  %s%s", argument.name, reqStr, helpText))
		end
		print()
	end

	-- Print Options section if there are any flags/options
	local options: { ArgData } = {}
	for _, argument in self.arguments do
		if argument.kind ~= "positional" then
			table.insert(options, argument)
		end
	end

	-- Always show Options section (even if empty, to show help flag)
	print("Options:")

	-- Print all options
	for _, argument in options do
		local aliasStr = table.concat(argument.options.aliases or {}, ", ")
		local helpText = argument.options.help or ""

		if aliasStr ~= "" then
			if argument.kind == "option" then
				print(string.format("  -%s, --%s <VALUE>  %s", aliasStr, argument.name, helpText))
			else
				print(string.format("  -%s, --%s  %s", aliasStr, argument.name, helpText))
			end
		else
			if argument.kind == "option" then
				print(string.format("  --%s <VALUE>  %s", argument.name, helpText))
			else
				print(string.format("  --%s  %s", argument.name, helpText))
			end
		end
	end

	-- Always show help option
	print("  -h, --help  Print help")
end

return cli
