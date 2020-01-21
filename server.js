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

app.get('/authentication/initiate', (req, res) => {

    const randOpts = { length: 10, type: 'base64' }
    const state_param = cryptoRandomString(randOpts)
    const password = cryptoRandomString(randOpts)

    const today = moment()
    const tomorrow = moment().add(1, 'day').startOf('day')
    const secsTillTomorrow = tomorrow.diff(today, 'seconds')

    const cipher = crypto.createCipher('aes-128-cbc', password)
    let state_param_encrypted = cipher.update(state_param, 'utf8', 'hex')
    state_param_encrypted += cipher.final('hex')

    stateParamCache.set(state_param_encrypted, {
        password,
        state_param
    }, secsTillTomorrow)

    const state = state_param_encrypted
    const scope = 'user-top-read'
    const spotify_authorization_url = 
        'https://accounts.spotify.com/authorize'
        + '?response_type=code'
        + `&client_id=${CLIENT_ID}`
        + `&redirect_uri=${REDIRECT_URI}`
        + `&state=${state}`
        + `&scope=${scope}`
        
    res.send({ spotify_authorization_url })
})

app.get('/authentication/callback', async (req, res) => {

    const { state: state_param_encrypted, code } = req.query
    if (!state_param_encrypted || !code) {
        return res.status(500).send({ code: 'MISSING PARAMS ERROR' })
    }

    const stateParamVals = stateParamCache.get(state_param_encrypted)
    if (!stateParamVals) {
        return res.status(401).send({ code: 'STATE PARAM ERROR' })
    }

    stateParamCache.del(state_param_encrypted)

    const { password, state_param } = stateParamVals
    let isValidParam

    try {
        const decipher = crypto.createDecipher('aes-128-cbc', password)
        let param_decrypted = decipher.update(state_param_encrypted, 'hex', 'utf8')
        param_decrypted += decipher.final('utf8')

        isValidParam =  param_decrypted === state_param

        if (!isValidParam) throw new Error()
    } catch(e) {
        return res.status(401).send({ code: 'STATE PARAM ERROR' })
    }

    if (isValidParam) {

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

        const tokenData = await axios.post(TOKEN_URL, tokenReqData, tokenReqConfig)
            .then(({ data: tokenData }) => tokenData)
            .catch(error => {
                console.log(error.response)
                return null
            })
        if (!tokenData) {
            return res.status(500).send({ code: 'TOKEN FETCH ERROR'  })
        }

        const { refresh_token, access_token, expires_in } = tokenData


        const ME_URL = 'https://api.spotify.com/v1/me' 
        const meReqConfig = {
            headers: { Authorization: `Bearer ${access_token}` }
        }
        const meData = await axios.get(ME_URL, meReqConfig)
            .then(({ data: meData }) => meData).catch(error => {
                console.log(error.response)
                return null
            })
        if (!meData) {
            return res.status(500).send({ code: 'ME FETCH ERROR'  })
        }
        const { id: spotify_id } = meData

        
        const today = moment()
        const tomorrow = moment().add(1, 'day').startOf('day')
        const secsTillTomorrow = tomorrow.diff(today, 'seconds')

        const expires_at = moment().add(expires_in, 'seconds').toDate()
        

        // how to deal with fetching self data?
        // reauthorize vs authorize endpoint?


        tokenCache.set(access_token, {
            expires_at,
            refresh_token,
            spotify_id,
        }, secsTillTomorrow)
        
        await TokenData.create({
            refresh_token,
            access_token, 
            expires_at
        })

        const accessTokenEncoded = Base64.encode(access_token)
        
        res.cookie(COOKIE_NAME, accessTokenEncoded)
        return res.send({ 
            me_data: meData,
            token_data: {
                refresh_token, 
                access_token: accessTokenEncoded, 
                expires_in
            }//
        })
    }
})

app.post('/authentication/authorize', async (req, res) => {

    const { token: headerToken } = req
    const { access_token: bodyToken  } = req.body

    if (!headerToken && !bodyToken) {
        return res.status(400).send({ code: 'MISSING TOKEN ERROR' })
    }

    const accessTokenEncoded = headerToken ? headerToken : bodyToken
    const accessToken = Base64.decode(accessTokenEncoded)

    const inCache = tokenCache.get(accessToken)

    if (inCache) {

        const { expires_at, refresh_token } = inCache
        
        const now = new Date()
        const tokenExpired = now > expires_at

        if (tokenExpired) {
            // refresh using refresh_token
            // store new token data
            // set new cookie
            // return result
        } else {
            return res.send({ code: 'AUTHORIZED' })
        }

    } else {

        const tokenDataRecord = await TokenData.findOne({ access_token: accessToken })

        if (!tokenDataRecord)  {
            return res.status(401).send({ code: 'UNAUTHORIZED' })
        } 

        const { expires_at, refresh_token, spotify_id } = tokenDataRecord

        const now = new Date()
        const tokenExpired = now > expires_at
        if (tokenExpired) {
            // refresh using refresh_token
            // store new token data
            // set new cookie
            // return result
        } else {

            const today = moment()
            const tomorrow = moment().add(1, 'day').startOf('day')
            const secsTillTomorrow = tomorrow.diff(today, 'seconds')
    
            tokenCache.set(accessToken, {
                expires_at,
                refresh_token,
                spotify_id,
            }, secsTillTomorrow)

            res.cookie(COOKIE_NAME, accessTokenEncoded)
            return res.send({ code: 'AUTHORIZED' })
        }
    }
})

app.post('/authentication/re-authorize', async (req, res) => {

    const { token: headerToken } = req
    const { access_token: bodyToken  } = req.body

    if (!headerToken && !bodyToken) {
        return res.status(400).send({ code: 'MISSING TOKEN ERROR' })
    }

    const accessTokenEncoded = headerToken ? headerToken : bodyToken
    const accessToken = Base64.decode(accessTokenEncoded)

    const inCache = tokenCache.get(accessToken)

    if (inCache) {

        const { expires_at, refresh_token } = inCache
        
        const now = new Date()
        const tokenExpired = now > expires_at

        if (tokenExpired) {
            // refresh using refresh_token
            // store new token data
            // set new cookie
            // return result
        } else {

            const ME_URL = 'https://api.spotify.com/v1/me' 
            const meReqConfig = {
                headers: { Authorization: `Bearer ${accessToken}` }
            }
            const meData = await axios.get(ME_URL, meReqConfig)
                .then(({ data: meData }) => meData).catch(error => {
                    console.log(error.response)
                    return null
                })
            if (!meData) {
                return res.status(500).send({ code: 'ME FETCH ERROR'  })
            }
            const tokenData = {
                expires_at, 
                refresh_token,
                access_token: accessTokenEncoded
            }//

            res.cookie(COOKIE_NAME, accessTokenEncoded)
            return res.send({ 
                me_data: meData,
                token_data: tokenData//
            })
        }

    } else {

        const tokenDataRecord = await TokenData.findOne({ access_token: accessToken })

        if (!tokenDataRecord)  {
            return res.status(401).send({ code: 'UNAUTHORIZED' })
        } 

        const { expires_at, refresh_token, spotify_id } = tokenDataRecord

        const now = new Date()
        const tokenExpired = now > expires_at
        if (tokenExpired) {
            // refresh using refresh_token
            // store new token data
            // set new cookie
            // return result
        } else {


            const ME_URL = 'https://api.spotify.com/v1/me' 
            const meReqConfig = {
                headers: { Authorization: `Bearer ${accessToken}` }
            }
            const meData = await axios.get(ME_URL, meReqConfig)
                .then(({ data: meData }) => meData).catch(error => {
                    console.log(error.response)
                    return null
                })
            if (!meData) {
                return res.status(500).send({ code: 'ME FETCH ERROR'  })
            }

            const today = moment()
            const tomorrow = moment().add(1, 'day').startOf('day')
            const secsTillTomorrow = tomorrow.diff(today, 'seconds')

            tokenCache.set(accessToken, {
                expires_at,
                refresh_token,
                spotify_id,
            }, secsTillTomorrow)

            const tokenData = {
                expires_at, 
                refresh_token,
                access_token: accessToken
            }//

            res.cookie(COOKIE_NAME, accessToken)
            return res.send({ 
                me_data: meData,
                token_data: tokenData//
            })
        }
    }
})

mongoose.connect(`${DB_URL}/authentication-api`, () => {
    app.listen(PORT, () => {
        console.log(`Authentication API running on PORT ${PORT}!`)
    })
})
