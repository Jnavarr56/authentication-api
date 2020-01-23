import mongoose from 'mongoose'
import express from 'express'
import cors from 'cors'
import { TokenData } from './db/models'
import NodeCache from 'node-cache'
import morgan from 'morgan'
import bearerToken from 'express-bearer-token'
import bodyParser from 'body-parser'
import { 
    getTimeTillTomorrow, 
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
import { 
    fetchMeData,
    fetchSpotifyTokens,
    refreshToken
} from './utils/spotify'
import { 
    checkForRequiredVars
} from './utils/vars'

require('dotenv').config()

checkForRequiredVars({
    CORS: false,
    PORT: true,
    DB_URL: true,
    COOKIE_NAME: true,
    SPOTIFY_AUTH_REDIRECT_URI: true,
    SPOTIFY_AUTH_CLIENT_ID: true,
    SPOTIFY_AUTH_CLIENT_SECRET:true
})

const { 
    CORS,
    PORT,
    DB_URL,
    COOKIE_NAME,
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

const cacheTokenData = async (tokenData, spotifyId) => {
    const {
        access_token,
        refresh_token,
        expires_in
    } = tokenData
    tokenCache.set(access_token,  {
        refresh_token: refresh_token,
        expires_at: getExpiresAtDate(expires_in),
        spotify_id: spotifyId
    }, getTimeTillTomorrow('seconds'))
}

const saveTokenData = async (tokenData, spotifyId) => {
    const {
        access_token,
        refresh_token,
        expires_in
    } = tokenData

    await TokenData.create({
        refresh_token: refresh_token,
        expires_at: getExpiresAtDate(expires_in),
        spotify_id: spotifyId,
        access_token
    })
}

app.get('/authentication/initiate', (req, res) => {
    
    const [ stateParam, password ] = generateRandomCryptoPair()
    const stateParamEncrypted = encryptWithPassword(stateParam, password)

    stateParamCache.set(stateParamEncrypted, {
        stateParam,
        password
    }, getTimeTillTomorrow('seconds'))

    const scope = 'user-top-read'
    const spotify_authorization_url = 
        'https://accounts.spotify.com/authorize'
        + '?response_type=code'
        + `&client_id=${CLIENT_ID}`
        + `&redirect_uri=${REDIRECT_URI}`
        + `&state=${stateParamEncrypted}`
        + `&scope=${scope}`
        
    res.send({ spotify_authorization_url })
})

app.get('/authentication/callback', async (req, res) => {

    const { state: stateParamEncrypted, code } = req.query
    if (!stateParamEncrypted || !code)
        return res.status(500).send({ code: 'MISSING PARAMS ERROR' })
    

    const stateParamInCache = stateParamCache.get(stateParamEncrypted)
    if (!stateParamInCache) 
        return res.status(401).send({ code: 'UNRECOGNIZED STATE ERROR' })
    

    stateParamCache.del(stateParamEncrypted)
    const { password, stateParam } = stateParamInCache
    
    const isValidParam = stateParam === decryptWithPassword(stateParamEncrypted, password)
    if (!isValidParam) return res.status(401).send({ code: 'UNRECOGNIZED STATE ERROR' })
    
    const tokenData = await fetchSpotifyTokens(code)
    if (!tokenData) return res.status(500).send({ code: 'TOKEN FETCH ERROR'  })

    const me_data = await fetchMeData(tokenData.access_token)
    if (!me_data) return res.status(500).send({ code: 'ME FETCH ERROR'  })

    const { id: spotify_id }  = me_data
    cacheTokenData(tokenData, spotify_id)
    await saveTokenData(tokenData, spotify_id)

    const access_token_encoded = encodeAccessToken(tokenData.access_token)

    res.cookie(COOKIE_NAME, access_token_encoded)
    return res.send({ 
        me_data,
        token_data: { access_token: access_token_encoded }
    })
})

app.post('/authentication/authorize', async (req, res) => {

    const { token: headerToken } = req
    const { access_token: bodyToken  } = req.body
    if (!headerToken && !bodyToken) {
        return res.status(400).send({ code: 'MISSING TOKEN ERROR' })
    }
    
    const accessTokenEncoded = headerToken || bodyToken
    const accessToken = decodeAccessToken(accessTokenEncoded)

    
    const tokenData = 
        tokenCache.get(accessToken) || await TokenData.findOne({ access_token: accessToken  })
    if (!tokenData) return res.status(401).send({ code: 'TOKEN NOT RECOGNIZED' })

    const { 
        spotify_id,
        expires_at, 
        refresh_token
    } = tokenData

    if (isTokenExpired(expires_at)) {
        
        const refreshedTokenData = await refreshToken(refresh_token)
        if (!refreshedTokenData.refresh_token) refreshedTokenData.refresh_token = refresh_token

        tokenCache.del(accessToken)
        cacheTokenData(refreshedTokenData, spotify_id)
        saveTokenData(refreshedTokenData, spotify_id)

        const accessTokenEncoded = encodeAccessToken(refreshedTokenData.access_token)

        res.cookie(COOKIE_NAME, accessTokenEncoded)
        return res.send({
            spotify_id,
            code: 'AUTHORIZED',
            refreshed_token_data: { access_token: accessTokenEncoded }
        })        
    }

    return res.send({ spotify_id, code: 'AUTHORIZED' })
})

app.post('/authentication/re-authorize', async (req, res) => {

    const { token: headerToken } = req
    const { access_token: bodyToken  } = req.body

    if (!headerToken && !bodyToken) {
        return res.status(400).send({ code: 'MISSING TOKEN ERROR' })
    }

    const accessTokenEncoded = headerToken || bodyToken
    const access_token = decodeAccessToken(accessTokenEncoded)
    
    const tokenData = tokenCache.get(access_token) || await TokenData.findOne({ access_token })
    if (!tokenData) return res.status(401).send({ code: 'TOKEN NOT RECOGNIZED' })

    const { 
        spotify_id,
        expires_at, 
        refresh_token
    } = tokenData


    if (isTokenExpired(expires_at)) {
        
        const refreshedTokenData = await refreshToken(refresh_token)
        if (!refreshedTokenData.refresh_token) refreshedTokenData.refresh_token = refresh_token

        tokenCache.del(access_token)
        cacheTokenData(refreshedTokenData, spotify_id)
        saveTokenData(refreshedTokenData, spotify_id)

        const access_token_encoded = encodeAccessToken(refreshedTokenData.access_token)

        res.cookie(COOKIE_NAME, access_token_encoded)
        return res.send({
            code: 'AUTHORIZED',
            spotify_id,
            refreshed_token_data: { access_token: access_token_encoded }
        })        
    }

    return res.send({ spotify_id, code: 'AUTHORIZED' })        
})

const dbOpts = { useNewUrlParser: true,  useUnifiedTopology: true }
mongoose.connect(`${DB_URL}/authentication-api`, dbOpts, () => {
    app.listen(PORT, () => {
        console.log(`Authentication API running on PORT ${PORT}!`)
    })
})
