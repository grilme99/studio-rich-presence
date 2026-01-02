export type ActivityAssets = {
	largeImage: string?,
	largeText: string?,

	smallImage: string?,
	smallText: string?,
}

export type Activity = {
	name: string,
	details: string,
	state: string,

	assets: ActivityAssets?,
}

return nil
