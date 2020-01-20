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

require('dotenv').config()

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

const app = express()
app.use(cors())

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

    const stateParamVals = stateParamCache.get(state_param_encrypted)
    if (!stateParamVals) {
        return res.status(401).send({ code: 'STATE PARAM ERROR' })
    }

    const { password, state_param } = stateParamVals
    let isValidParam

    try {
        const decipher = crypto.createDecipher('aes-128-cbc', password)
        let param_decrypted = decipher.update(state_param_encrypted, 'hex', 'utf8')
        param_decrypted += decipher.final('utf8')

        stateParamCache.del(state_param_encrypted)

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
            headers: {
                Authorization: `Basic ${encodedCredentials}`
            },
            'Content-Type': tokenReqContentType
        }
        const tokenReqData = qs.stringify({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: REDIRECT_URI
        })

        const tokenData = await axios.post(TOKEN_URL, tokenReqData, tokenReqConfig)
            .then(({ data: tokenData }) => tokenData).catch(error => null)
        if (!tokenData) {
            return res.status(500).send({ code: 'TOKEN FETCH ERROR'  })
        }

        const {
            refresh_token,
            access_token
        } = tokenData
        const ME_URL = 'https://api.spotify.com/v1/me' 
        const meReqConfig = {
            headers: {
                Authorization: `Bearer ${access_token}`
            }
        }
        const meData = await axios.post(ME_URL, meReqConfig)
            .then(({ data: meData }) => meData).catch(error => null)
        if (!meData) {
            return res.status(500).send({ code: 'ME FETCH ERROR'  })
        }

        return res.send({ me_data: meData }) 

    }       

})

mongoose.connect(`${DB_URL}/authentication-api`, () => {
    app.listen(PORT, () => {
        console.log(`Authentication API running on PORT ${PORT}!`)
    })
})
