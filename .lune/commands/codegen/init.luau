--[[
	Codegen Command
	
	Runs all code generation tasks: compiles networking, generates project links,
	and generates the sourcemap.
]]

local color = require("../utils/color")
local rojo = require("../lib/project/rojo")

local codegen = {}

-- Metadata for help command
codegen.name = "codegen"
codegen.description = "Runs all code generation (sourcemap only for now)"
codegen.usage = "lune run codegen"

-- Argument definitions for CLI parsing
codegen.arguments = {}

export type Options = {
	quiet: boolean?,
	generateSourcemap: boolean?,
}

--[[
	Runs all code generation tasks.
	
	@param options Configuration options
	@return True if successful, false otherwise
]]
function codegen.run(options_: Options?): boolean
	local options: Options = options_ or {}
	local quiet = if options.quiet ~= nil then options.quiet else false

	if options.generateSourcemap then
		-- Generate sourcemap
		local sourcemapSuccess, sourcemapError = rojo.sourcemap({
			projectFile = "plugin/default.project.jsonc",
			output = "sourcemap.json",
			absolute = true,
		})
		if not sourcemapSuccess then
			if not quiet then
				print(color.bold(color.red("Failed to generate sourcemap")))
				print(sourcemapError)
			end
			return false
		end
	end

	if not quiet then
		print(color.bold(color.green("Code generation complete!")))
	end

	return true
end

return codegen
