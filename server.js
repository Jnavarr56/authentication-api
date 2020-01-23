import mongoose from 'mongoose'
import express from 'express'
import cors from 'cors'
import crypto from 'crypto'
import cryptoRandomString from 'crypto-random-string'
import moment from 'moment'
import { Base64 } from 'js-base64'
import { TokenData } from './db'
import qs from 'querystring'
import axios from 'axios'
import NodeCache from 'node-cache'
import morgan from 'morgan'
import bearerToken from 'express-bearer-token'
import bodyParser from 'body-parser'

require('dotenv').config()

const COOKIE_NAME = 'speeterfoo'
const { 
    PORT,
    DB_URL,
    SPOTIFY_AUTH_REDIRECT_URI: REDIRECT_URI, 
    SPOTIFY_AUTH_CLIENT_ID: CLIENT_ID,
    SPOTIFY_AUTH_CLIENT_SECRET: CLIENT_SECRET
} = process.env
if (!PORT || !DB_URL) {
    console.log('Must Supply a DB_URL and PORT.\nShutting Down.')
    process.exit(1)
}

const stateParamCache = new NodeCache()
const tokenCache = new NodeCache()

const app = express()
app
    .use(cors())
    .use(bearerToken())
    .use(bodyParser.json())
    .use(bodyParser.urlencoded({ extended: true }))
    .use(morgan('dev'))


const getTimeTillTomorrow = timeUnit => {
    const today = moment()
    const tomorrow = moment().add(1, 'day').startOf('day')
    return tomorrow.diff(today, timeUnit)
}

const encodeAccessToken = accessToken => Base64.encode(accessToken)

const decodeAccessToken = accessToken => Base64.decode(accessToken)

const generateRandomCryptoPair = options => {
    let randOpts = options ? options : { length: 10,  type: 'base64' }
    return [ cryptoRandomString(randOpts), cryptoRandomString(randOpts) ]
}

const encryptWithPassword = (valToEncrypt, password) => {
    const cipher = crypto.createCipher('aes-128-cbc', password)
    let encryptedVal = cipher.update(valToEncrypt, 'utf8', 'hex')
    encryptedVal += cipher.final('hex')
    return encryptedVal
}

const decryptWithPassword = (valToDecrypt, password) => {
    let val
    try {
        const decipher = crypto.createDecipher('aes-128-cbc', password)
        let valDecrypted = decipher.update(valToDecrypt, 'hex', 'utf8')
        valDecrypted += decipher.final('utf8')
        val = valDecrypted
    } catch(e) {
        val = null
    }
    return val
}

const fetchSpotifyTokens = async code => {
    const encodedCredentials = Base64.encode(`${CLIENT_ID}:${CLIENT_SECRET}`)        
    const TOKEN_URL = 'https://accounts.spotify.com/api/token'
    const tokenReqContentType = 'application/x-www-form-urlencoded'
    const tokenReqConfig = {
        headers: { Authorization: `Basic ${encodedCredentials}` },
        'Content-Type': tokenReqContentType
    }
    const tokenReqData = qs.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: REDIRECT_URI
    })
    return axios.post(TOKEN_URL, tokenReqData, tokenReqConfig)
        .then(({ data: tokenData }) => tokenData)
        .catch(error => {
            console.log(error.response)
            return null
        })
}

const fetchMeData = async accessToken => {
    const ME_URL = 'https://api.spotify.com/v1/me' 
    const meReqConfig = {
        headers: { Authorization: `Bearer ${accessToken}` }
    }
    return axios.get(ME_URL, meReqConfig)
        .then(({ data: meData }) => meData).catch(error => {
            console.log(error.response)
            return null
        })
}

const refreshToken = async refreshToken => {
    const encodedCredentials = Base64.encode(`${CLIENT_ID}:${CLIENT_SECRET}`)        
    const REFRESH_URL = 'https://accounts.spotify.com/api/token'
    const refreshReqContentType = 'application/x-www-form-urlencoded'
    const refreshReqConfig = {
        headers: { Authorization: `Basic ${encodedCredentials}` },
        'Content-Type': refreshReqContentType
    }
    const refreshData = qs.stringify({
        grant_type: 'refresh_token',
        refresh_token: refreshToken
    })
    return axios.post(REFRESH_URL, refreshData, refreshReqConfig)
        .then(({ data: tokenData }) => tokenData).catch(error => {
            console.log(error.response)
            return null
        })
}

const getExpiresAtDate = secs => moment().add(secs, 'seconds').toDate()

const isTokenExpired = expiresAt => new Date() > expiresAt

const cacheTokenData = async (tokenData, spotifyId) => {
    const {
        access_token,
        refresh_token,
        expires_in
    } = tokenData

    const cacheableData = {
        refresh_token: refresh_token,
        expires_at: getExpiresAtDate(expires_in),
        spotify_id: spotifyId
    }
    tokenCache.set(access_token, cacheableData, getTimeTillTomorrow('seconds'))
}

const saveTokenData = async (tokenData, spotifyId) => {
    const {
        access_token,
        refresh_token,
        expires_in
    } = tokenData

    const saveableData = {
        refresh_token: refresh_token,
        expires_at: getExpiresAtDate(expires_in),
        spotify_id: spotifyId,
        access_token
    }

    await TokenData.create(saveableData)
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
