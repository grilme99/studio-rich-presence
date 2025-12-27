local process = require("@lune/process")
local stdio = require("@lune/stdio")
local task = require("@lune/task")

local IS_CI = process.env.CI ~= nil

local CLEAR_LINE = "\x1b[2K\r"
local SPINNER_FRAMES = { "◜", "◝", "◞", "◟" }

local function createSpinner()
	local spinner = {
		animating = false,
		animateThread = nil :: thread?,
		text = "",
		frame = 1,
	}

	function spinner.setText(newText: string)
		spinner.text = tostring(newText)
	end

	function spinner.start()
		if spinner.animateThread then
			return
		end

		spinner.animating = not IS_CI
		spinner.frame = 1
		spinner.animateThread = task.spawn(function()
			while spinner.animating do
				stdio.write(
					CLEAR_LINE
						.. stdio.style("bold")
						.. stdio.color("green")
						.. SPINNER_FRAMES[spinner.frame]
						.. stdio.style("reset")
						.. stdio.color("reset")
						.. " "
						.. spinner.text
				)

				spinner.frame += 1
				if spinner.frame > #SPINNER_FRAMES then
					spinner.frame = 1
				end

				task.wait(1 / 20)
			end
		end)
	end

	function spinner.stop()
		spinner.animating = false
		if spinner.animateThread then
			task.cancel(spinner.animateThread)
			spinner.animateThread = nil
		end

		spinner.text = ""
		spinner.frame = 1

		stdio.write(CLEAR_LINE)
	end

	return spinner
end

return createSpinner
