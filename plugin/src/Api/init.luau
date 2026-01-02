local Api = require(script.Api)

export type AuthStartRequest = Api.AuthStartRequest
export type AuthStartResponse = Api.AuthStartResponse
export type AuthCompleteRequest = Api.AuthCompleteRequest
export type AuthCompleteResponse = Api.AuthCompleteResponse

export type ListAccountsResponse = Api.ListAccountsResponse
export type LinkedAccount = Api.LinkedAccount

export type UpdatePresenceRequest = Api.UpdatePresenceRequest
export type UpdatePresenceResponse = Api.UpdatePresenceResponse
export type ClearPresenceRequest = Api.ClearPresenceRequest
export type ClearPresenceResponse = Api.ClearPresenceResponse
export type DiscordPresence = Api.DiscordPresence
export type PresenceTimestamps = Api.PresenceTimestamps
export type PresenceAssets = Api.PresenceAssets

export type ErrorResponse = Api.ErrorResponse
export type ErrorCode = Api.ErrorCode

export type Credentials = Api.Credentials
export type ApiError = Api.ApiError
export type ApiErrorType = Api.ApiErrorType

export type ApiConfig = Api.ApiConfig
export type ApiClient = Api.ApiClient

return Api
