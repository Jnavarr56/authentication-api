import { Base64 } from 'js-base64'
import axios from 'axios'
import qs from 'querystring'

require('dotenv').config()

const { 
    SPOTIFY_AUTH_REDIRECT_URI: REDIRECT_URI, 
    SPOTIFY_AUTH_CLIENT_ID: CLIENT_ID,
    SPOTIFY_AUTH_CLIENT_SECRET: CLIENT_SECRET
} = process.env


const TOKEN_URL = 'https://accounts.spotify.com/api/token'
const ME_URL = 'https://api.spotify.com/v1/me' 
const encodedCredentials = Base64.encode(`${CLIENT_ID}:${CLIENT_SECRET}`)
const basicAuthorization = `Basic ${encodedCredentials}`
const formURLEncodedContentType = 'application/x-www-form-urlencoded'

export async function fetchSpotifyTokens(code) {
    const config = {
        headers: { Authorization: basicAuthorization },
        'Content-Type': formURLEncodedContentType
    }
    const data = qs.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: REDIRECT_URI
    })
    return axios.post(TOKEN_URL, data, config)
        .then(({ data: tokenData }) => tokenData)
        .catch(error => {
            console.log(error.response)
            return null
        })
}

export async function fetchMeData(accessToken) {
    const headers = { Authorization: `Bearer ${accessToken}` }
    return axios.get(ME_URL, { headers })
        .then(({ data: meData }) => meData).catch(error => {
            console.log(error.response)
            return null
        })
}

export async function refreshToken(refreshToken) {
    const config = {
        headers: { Authorization: basicAuthorization },
        'Content-Type': formURLEncodedContentType
    }
    const data = qs.stringify({
        grant_type: 'refresh_token',
        refresh_token: refreshToken
    })
    return axios.post(TOKEN_URL, data, config)
        .then(({ data: tokenData }) => tokenData).catch(error => {
            console.log(error.response)
            return null
        })
}