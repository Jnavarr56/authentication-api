import { getSecsTillFuture } from './time'

require('dotenv').config()

const TOKEN_CACHE_TIME_UNIT = process.env.TOKEN_CACHE_TIME_UNIT || 'seconds'
const TOKEN_CACHE_TIME_VAL = process.env.TOKEN_CACHE_TIME_VAL || 1

export async function storeTokenData(dataToStore, storeLocations) {
	const {
		access_token,
		refresh_token,
		expires_at,
		user_id,
		spotify_id
	} = dataToStore

	const { model, nodeCache } = storeLocations

	const dbSaveSuccessful = await model
		.create({
			access_token,
			refresh_token,
			expires_at,
			user_id,
			spotify_id
		})
		.then(newTokenData => newTokenData)
		.catch(error => {
			console.log(error)
			return null
		})

	if (!dbSaveSuccessful) return null

	nodeCache.set(
		access_token,
		{
			refresh_token,
			expires_at,
			spotify_id,
			user_id
		},
		getSecsTillFuture(TOKEN_CACHE_TIME_VAL, TOKEN_CACHE_TIME_UNIT)
	)

	return true
}

export async function retrieveTokenData(accessToken, storeLocations) {
	const { model, nodeCache } = storeLocations

	const inCache = nodeCache.get(accessToken)
	if (inCache) return inCache

	return await model
		.findOne({ access_token: accessToken })
		.then(tokenData => tokenData)
		.catch(error => {
			console.log(error)
			return null
		})
}
