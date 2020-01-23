import crypto from 'crypto'
import cryptoRandomString from 'crypto-random-string'
import { Base64 } from 'js-base64'

export function encodeAccessToken(accessToken) {
    return Base64.encode(accessToken)
}

export function decodeAccessToken(accessToken) {
    return Base64.decode(accessToken)
}

export function generateRandomCryptoPair(options) {
    const randOpts = options ? options : { length: 10,  type: 'base64' }
    return [ cryptoRandomString(randOpts), cryptoRandomString(randOpts) ]
}

export function encryptWithPassword(valToEncrypt, password) {
    const cipher = crypto.createCipher('aes-128-cbc', password)
    let encryptedVal = cipher.update(valToEncrypt, 'utf8', 'hex')
    encryptedVal += cipher.final('hex')
    return encryptedVal
}

export function decryptWithPassword(valToDecrypt, password) {
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