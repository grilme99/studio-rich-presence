-- The events in this file mirror the TelementryEventName enum in the backend.
-- The backend must be updated first before adding new events.

export type AppOpened = {
	eventName: "AppOpened",
}

export type AppClosed = {
	eventName: "AppClosed",
}

export type TelemetryOptedIn = {
	eventName: "TelemetryOptedIn",
}

export type TelemetryOptedOut = {
	eventName: "TelemetryOptedOut",
}

export type TelemetryEvent = AppOpened | AppClosed | TelemetryOptedIn | TelemetryOptedOut

return nil
