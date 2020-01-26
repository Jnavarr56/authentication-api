import crypto from 'crypto'
import { Base64 } from 'js-base64'

const IV_LENGTH = 16

export function encodeAccessToken(accessToken) {
	return Base64.encode(accessToken)
}

export function decodeAccessToken(accessToken) {
	return Base64.decode(accessToken)
}

export function encryptWithPassword(valToEncrypt, password) {
	const iv = crypto.randomBytes(IV_LENGTH)
	const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(password), iv)
	let encrypted = cipher.update(valToEncrypt);
   
	encrypted = Buffer.concat([encrypted, cipher.final()])
   
	return iv.toString('hex') + ':' + encrypted.toString('hex')
}

export function decryptWithPassword(valToDecrypt, password) {
	try {
		const textParts = valToDecrypt.split(':');
		const iv = Buffer.from(textParts.shift(), 'hex')
		const encryptedText = Buffer.from(textParts.join(':'), 'hex');
		const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(password), iv)
		let decrypted = decipher.update(encryptedText)
	   
		decrypted = Buffer.concat([decrypted, decipher.final()]);
	   
		return decrypted.toString()
	} catch(e) {
		return null
	}
}
