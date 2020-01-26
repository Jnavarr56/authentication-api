import mongoose from 'mongoose'
import express from 'express'
import cors from 'cors'
import { TokenData } from './db/models'
import NodeCache from 'node-cache'
import morgan from 'morgan'
import bearerToken from 'express-bearer-token'
import bodyParser from 'body-parser'
import { getExpiresAtDate, isTokenExpired } from './utils/time'
import { encodeAccessToken, decodeAccessToken } from './utils/encryption'
import { fetchMeData, fetchSpotifyTokens, refreshToken } from './utils/spotify'
import { checkForRequiredVars } from './utils/vars'
import StateParamManager from './utils/classes/StateParamManager'
import UserActionsManager from './utils/classes/UserActionsManager'
import TokenStoreManager from './utils/classes/TokenStoreManager'

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
	'GATEWAY_BASE_URL',
])


const {
	CORS,
	PORT,
	DB_URL,
	AUTH_COOKIE_NAME,
	AUTHENTICATION_API,
	SPOTIFY_AUTH_REDIRECT_URI: REDIRECT_URI,
	SPOTIFY_AUTH_CLIENT_ID: CLIENT_ID
} = process.env


const tokenCache = new NodeCache()
const adminTokenCache = new NodeCache()
const stateParamCache = new NodeCache()

const tokenStoreManager = new TokenStoreManager({
	model: TokenData,
	cache: tokenCache
})
const stateParamManager = new StateParamManager(stateParamCache)
const userActionsManager = new UserActionsManager(adminTokenCache)


const app = express()
if (CORS) app.use(cors())

app
	.use(bearerToken())
	.use(bodyParser.json())
	.use(bodyParser.urlencoded({ extended: true }))
	.use(morgan('dev'))


app.get(`${AUTHENTICATION_API}/initiate`, (req, res) => {

	const encryptedStateParam = 
		stateParamManager.generateEncryptedStateParam()

	const scopes = [
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

	const spotify_authorization_url =
		'https://accounts.spotify.com/authorize' +
		'?response_type=code' +
		`&client_id=${CLIENT_ID}` +
		`&redirect_uri=${REDIRECT_URI}` +
		`&state=${encryptedStateParam}` +
		`&scope=${scopes}`

	res.send({ spotify_authorization_url })
})

app.get(`${AUTHENTICATION_API}/callback`, async (req, res) => {
	const { state: encryptedStateParam, code } = req.query

	if (!encryptedStateParam || !code)
		return res.status(500).send({ code: 'MISSING PARAMS ERROR' })

	try {
		stateParamManager.validateEncryptedStateParam(encryptedStateParam)
	} catch(e) {
		console.trace(e)
		return res.status(401).send({ code: 'UNRECOGNIZED STATE ERROR' })
	}
		
	try { 
		var tokenData = await fetchSpotifyTokens(code) 
	} catch(e) {
		console.trace(e)
		return res.status(500).send({ code: 'TOKEN FETCH ERROR' })
	}
		
	const { refresh_token, access_token, expires_in } = tokenData

	try { 
		var spotifyMeData = await fetchMeData(access_token) 
	} catch(e) {
		console.trace(e)
		return res.status(500).send({ code: 'ME FETCH ERROR' })
	}

	try { 
		var existingUser = await userActionsManager.checkIfUserExists(spotifyMeData.id) 
	} catch(e) {
		console.trace(e)
		return res.status(500).send({ code: 'USER FETCH ERROR' })
	}

	try {
		var userData = existingUser ||  await userActionsManager.createUser({
			app_name: spotifyMeData.display_name,
			display_name: spotifyMeData.display_name,
			country: spotifyMeData.country,
			email: spotifyMeData.email,
			spotify_id: spotifyMeData.id
		})
	} catch (e) {
		console.trace(e)
		return res.status(500).send({ code: 'USER CREATION ERROR' })
	}

	try {
		await tokenStoreManager.storeTokenData({
			access_token,
			refresh_token,
			user_id: userData._id,
			spotify_id: spotifyMeData.id,
			expires_at: getExpiresAtDate(expires_in),
		})
	} catch(e) {
		console.trace(e)
		return res.status(500).send({ code: 'TOKEN DATA STORE ERROR' })
	}
	
	
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


	if (adminTokenCache.get(encodedAccessToken)) {
		adminTokenCache.del(encodedAccessToken)
		return res.send({ code: 'ADMIN ACTION ACCEPTED' })
	}

	
	const currentAccessToken = decodeAccessToken(encodedAccessToken)


	try {
		var tokenData = await tokenStoreManager.retrieveTokenData(currentAccessToken)
	} catch(e) {
		return res.status(401).send({ code: 'TOKEN NOT RECOGNIZED ERROR' })
	}
	
	const {
		user_id,
		spotify_id,
		expires_at: currentExpiresAt,
		refresh_token: currentRefreshToken
	} = tokenData

	const responseVal = { user_id, spotify_id, code: 'AUTHORIZED' }

	if (isTokenExpired(currentExpiresAt)) {

		tokenCache.del(currentAccessToken)
			
		try {
			var refreshedTokenData = await refreshToken(currentRefreshToken)
		} catch(e) {
			return res.status(500).send({ code: 'TOKEN REFRESH ERROR' })
		}
		
		const {
			expires_in: newExpiresIn,
			access_token: newAccessToken,
			refresh_token: newRefreshToken,
		} = refreshedTokenData

		try {
			await tokenStoreManager.storeTokenData({
				user_id,
				spotify_id,
				access_token: newAccessToken,
				refresh_token: newRefreshToken || currentRefreshToken,
				expires_at: getExpiresAtDate(newExpiresIn)
			})
		} catch(e) {
			console.trace(e)
			return res.status(500).send({ code: 'TOKEN DATA STORE ERROR' })
		}

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

	try {
		var tokenData = await tokenStoreManager.retrieveTokenData(currentAccessToken)
	} catch(e) {
		return res.status(401).send({ code: 'TOKEN NOT RECOGNIZED ERROR' })
	}

	const {
		user_id,
		spotify_id,
		expires_at: currentExpiresAt,
		refresh_token: currentRefreshToken
	} = tokenData

	const responseVal = { code: 'RE-AUTHORIZED' }

	try { 
		responseVal.user_data = await userActionsManager.checkIfUserExists(spotify_id) 
	} catch(e) {
		console.trace(e)
		return res.status(500).send({ code: 'USER FETCH ERROR' })
	}

	if (!responseVal.user_data) 
		return res.status(400).send({ code: 'USER DOES NOT EXIST ERROR' })


	if (isTokenExpired(currentExpiresAt)) {

		tokenCache.del(currentAccessToken)

		try {
			var refreshedTokenData = await refreshToken(currentRefreshToken)
		} catch(e) {
			return res.status(500).send({ code: 'TOKEN REFRESH ERROR' })
		}
		

		const {
			expires_in: newExpiresIn,
			access_token: newAccessToken,
			refresh_token: newRefreshToken,
		} = refreshedTokenData


		try {
			await tokenStoreManager.storeTokenData({
				user_id,
				spotify_id,
				access_token: newAccessToken,
				refresh_token: newRefreshToken || currentRefreshToken,
				expires_at: getExpiresAtDate(newExpiresIn)
			})
		} catch(e) {
			console.trace(e)
			return res.status(500).send({ code: 'TOKEN DATA STORE ERROR' })
		}

		const newEncodedAccessToken = encodeAccessToken(newAccessToken)

		res.cookie(AUTH_COOKIE_NAME, newEncodedAccessToken, {
			domain: 'localhost',
			path: '/',
			httpOnly: false
		})

		responseVal.token_data = { access_token: newEncodedAccessToken }		

		currentAccessToken = newAccessToken
	}


	try { 
		responseVal.spotify_me_data = await fetchMeData(currentAccessToken) 
	} catch(e) {
		console.trace(e)
		return res.status(500).send({ code: 'ME FETCH ERROR' })
	}
		
	return res.send(responseVal)
})

const dbOpts = { useNewUrlParser: true, useUnifiedTopology: true }
mongoose.connect(`${DB_URL}/authentication-api`, dbOpts, () => {
	app.listen(PORT, () => {
		console.log(`Authentication API running on PORT ${PORT}!`)
	})
})
