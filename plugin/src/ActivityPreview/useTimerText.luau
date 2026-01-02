local Plugin = script:FindFirstAncestor("StudioRichPresence")

local Packages = Plugin.Packages
local React = require(Packages.React)

local useBinding = React.useBinding
local useEffect = React.useEffect

local function useTimerText(startTime: number): React.Binding<string>
	local timerText, setTimerText = useBinding("0:00")

	-- Every second, update the timer text with how much time has passed since
	-- the start time.
	useEffect(function()
		local isRunning = true

		task.spawn(function()
			while isRunning do
				local currentTime = os.time()

				local elapsedTime = currentTime - startTime
				local minutes = math.floor(elapsedTime / 60)
				local seconds = elapsedTime % 60

				setTimerText(`{minutes}:{seconds}`)

				task.wait(1)
			end
		end)

		return function()
			isRunning = false
		end
	end, { startTime })

	return timerText
end

return useTimerText
