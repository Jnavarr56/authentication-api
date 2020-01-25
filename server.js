import mongoose from 'mongoose'
import express from 'express'
import cors from 'cors'
import { TokenData } from './db/models'
import NodeCache from 'node-cache'
import morgan from 'morgan'
import bearerToken from 'express-bearer-token'
import bodyParser from 'body-parser'
import {
	getSecsTillFuture,
	getExpiresAtDate,
	isTokenExpired
} from './utils/time'
import {
	encodeAccessToken,
	decodeAccessToken,
	generateRandomCryptoPair,
	encryptWithPassword,
	decryptWithPassword
} from './utils/encryption'
import { fetchMeData, fetchSpotifyTokens, refreshToken } from './utils/spotify'
import { checkIfUserExists, createUser } from './utils/users'
import { retrieveTokenData, storeTokenData } from './utils/tokenStore'
import { checkForRequiredVars } from './utils/vars'

require('dotenv').config()

checkForRequiredVars([
	'PORT',
	'DB_URL',
	'AUTH_COOKIE_NAME',
	'SPOTIFY_AUTH_REDIRECT_URI',
	'SPOTIFY_AUTH_CLIENT_ID',
	'SPOTIFY_AUTH_CLIENT_SECRET',
	'AUTHENTICATION_API',
	'USERS_API',
	'GATEWAY_URL',
])

const SCOPE = [
	'user-top-read',
	'user-read-recently-played',
	'user-library-read',
	'user-read-playback-state',
	'user-read-email',
	'playlist-read-collaborative',
	'user-read-private',
	'user-read-currently-playing',
	'user-follow-read'
].join(' ')

const {
	CORS,
	PORT,
	DB_URL,
	AUTH_COOKIE_NAME,
	AUTHENTICATION_API,
	SPOTIFY_AUTH_REDIRECT_URI: REDIRECT_URI,
	SPOTIFY_AUTH_CLIENT_ID: CLIENT_ID
} = process.env

const stateParamCache = new NodeCache()
const tokenCache = new NodeCache()

const app = express()
if (CORS) app.use(cors())

app
	.use(bearerToken())
	.use(bodyParser.json())
	.use(bodyParser.urlencoded({ extended: true }))
	.use(morgan('dev'))

app.get(`${AUTHENTICATION_API}/initiate`, (req, res) => {
	const [ stateParam, password ] = generateRandomCryptoPair()
	const stateParamEncrypted = encryptWithPassword(stateParam, password)

	stateParamCache.set(
		stateParamEncrypted,
		{
			stateParam,
			password
		},
		getSecsTillFuture(1, 'day')
	)

	const spotify_authorization_url =
		'https://accounts.spotify.com/authorize' +
		'?response_type=code' +
		`&client_id=${CLIENT_ID}` +
		`&redirect_uri=${REDIRECT_URI}` +
		`&state=${stateParamEncrypted}` +
		`&scope=${SCOPE}`

	res.send({ spotify_authorization_url })
})

app.get(`${AUTHENTICATION_API}/callback`, async (req, res) => {
	const { state: stateParamEncrypted, code } = req.query
	if (!stateParamEncrypted || !code)
		return res.status(500).send({ code: 'MISSING PARAMS ERROR' })

	const stateParamInCache = stateParamCache.get(stateParamEncrypted)
	if (!stateParamInCache)
		return res.status(401).send({ code: 'UNRECOGNIZED STATE ERROR' })

	stateParamCache.del(stateParamEncrypted)
	const { password, stateParam } = stateParamInCache

	const decryptedStateParam = decryptWithPassword(stateParamEncrypted, password)
	const isValidParam = stateParam === decryptedStateParam

	if (!isValidParam)
		return res.status(401).send({ code: 'UNRECOGNIZED STATE ERROR' })

	const tokenData = await fetchSpotifyTokens(code)
	if (tokenData === null)
		return res.status(500).send({ code: 'TOKEN FETCH ERROR' })

	const { refresh_token, access_token, expires_in } = tokenData

	const spotifyMeData = await fetchMeData(access_token)
	if (spotifyMeData === null)
		return res.status(500).send({ code: 'ME FETCH ERROR' })

	let userData
	const existingUser = await checkIfUserExists(spotifyMeData.id)
	if (existingUser === null)
		return res.status(500).send({ code: 'USER FETCH ERROR' })

	if (existingUser === undefined) {
		userData = await createUser({
			app_name: spotifyMeData.display_name,
			display_name: spotifyMeData.display_name,
			country: spotifyMeData.country,
			email: spotifyMeData.email,
			spotify_id: spotifyMeData.id
		})

		if (!userData === null)
			return res.status(500).send({ code: 'USER CREATION ERROR' })
	} else {
		userData = existingUser
	}

	const storeSucessful = await storeTokenData(
		{
			access_token,
			refresh_token,
			expires_at: getExpiresAtDate(expires_in),
			spotify_id: spotifyMeData.id,
			user_id: userData._id
		},
		{ model: TokenData, nodeCache: tokenCache }
	)
	if (storeSucessful === null)
		return res.status(500).send({ code: 'TOKEN DATA STORE ERROR' })

	const accessTokenEncoded = encodeAccessToken(access_token)

	res.cookie(AUTH_COOKIE_NAME, accessTokenEncoded, {
		domain: 'localhost',
		path: '/',
		httpOnly: false
	})

	return res.send({
		user_data: userData,
		spotify_me_data: spotifyMeData,
		token_data: {
			access_token: accessTokenEncoded
		}
	})
})

app.get(`${AUTHENTICATION_API}/authorize`, async (req, res) => {
	const { token: encodedAccessToken } = req

	if (!encodedAccessToken)
		return res.status(400).send({ code: 'MISSING TOKEN ERROR' })

	const currentAccessToken = decodeAccessToken(encodedAccessToken)

	const tokenData = await retrieveTokenData(currentAccessToken, {
		model: TokenData,
		nodeCache: tokenCache
	})
	if (!tokenData) return res.status(401).send({ code: 'TOKEN NOT RECOGNIZED' })

	const {
		user_id,
		spotify_id,
		expires_at: currentExpiresAt,
		refresh_token: currentRefreshToken
	} = tokenData

	let responseVal = { user_id, spotify_id, code: 'AUTHORIZED' }

	if (isTokenExpired(currentExpiresAt)) {
		if (tokenCache.get(currentAccessToken)) tokenCache.del(currentAccessToken)

		const refreshedTokenData = await refreshToken(currentRefreshToken)
		if (!refreshedTokenData)
			return res.status(500).send({ code: 'TOKEN REFRESH ERROR' })

		const {
			expires_in: newExpiresIn,
			refresh_token: newRefreshToken,
			access_token: newAccessToken
		} = refreshedTokenData

		const storeSucessful = await storeTokenData(
			{
				user_id,
				spotify_id,
				access_token: newAccessToken,
				refresh_token: newRefreshToken || currentRefreshToken,
				expires_at: getExpiresAtDate(newExpiresIn)
			},
			{ model: TokenData, nodeCache: tokenCache }
		)

		if (!storeSucessful)
			return res.status(500).send({ code: 'TOKEN DATA STORE ERROR' })

		const newEncodedAccessToken = encodeAccessToken(newAccessToken)

		res.cookie(AUTH_COOKIE_NAME, newEncodedAccessToken, {
			domain: 'localhost',
			path: '/',
			httpOnly: false
		})

		responseVal.token_data = { access_token: newEncodedAccessToken }
	}

	return res.send(responseVal)
})

app.get(`${AUTHENTICATION_API}/re-authorize`, async (req, res) => {
	const { token: encodedAccessToken } = req

	if (!encodedAccessToken)
		return res.status(400).send({ code: 'MISSING TOKEN ERROR' })

	let currentAccessToken = decodeAccessToken(encodedAccessToken)

	const tokenData = await retrieveTokenData(currentAccessToken, {
		model: TokenData,
		nodeCache: tokenCache
	})
	if (!tokenData) return res.status(401).send({ code: 'TOKEN NOT RECOGNIZED' })

	const {
		user_id,
		spotify_id,
		expires_at: currentExpiresAt,
		refresh_token: currentRefreshToken
	} = tokenData

	let responseVal = { code: 'RE-AUTHORIZED' }

	if (isTokenExpired(currentExpiresAt)) {
		if (tokenCache.get(currentAccessToken)) tokenCache.del(currentAccessToken)

		const refreshedTokenData = await refreshToken(currentRefreshToken)
		if (!refreshedTokenData)
			return res.status(500).send({ code: 'TOKEN REFRESH ERROR' })

		const {
			expires_in: newExpiresIn,
			refresh_token: newRefreshToken,
			access_token: newAccessToken
		} = refreshedTokenData

		const storeSucessful = await storeTokenData(
			{
				user_id,
				spotify_id,
				access_token: newAccessToken,
				refresh_token: newRefreshToken || currentRefreshToken,
				expires_at: getExpiresAtDate(newExpiresIn)
			},
			{ model: TokenData, nodeCache: tokenCache }
		)

		if (!storeSucessful)
			return res.status(500).send({ code: 'TOKEN DATA STORE ERROR' })

		const newEncodedAccessToken = encodeAccessToken(currentAccessToken)

		res.cookie(AUTH_COOKIE_NAME, newEncodedAccessToken, {
			domain: 'localhost',
			path: '/',
			httpOnly: false
		})

		responseVal.token_data = { access_token: newEncodedAccessToken }
	}

	const spotifyMeData = await fetchMeData(currentAccessToken)
	if (spotifyMeData === null)
		return res.status(500).send({ code: 'ME FETCH ERROR' })

	const existingUser = await checkIfUserExists(spotifyMeData.id)
	if (existingUser === null)
		return res.status(500).send({ code: 'USER FETCH ERROR' })
	if (existingUser === undefined)
		return res.status(400).send({ code: 'USER DOES NOT EXIST ERROR' })

	return res.send({
		...responseVal,
		user_data: existingUser,
		spotify_me_data: spotifyMeData
	})
})

const dbOpts = { useNewUrlParser: true, useUnifiedTopology: true }
mongoose.connect(`${DB_URL}/authentication-api`, dbOpts, () => {
	app.listen(PORT, () => {
		console.log(`Authentication API running on PORT ${PORT}!`)
	})
})
