import axios from '../axios-config/axios'
import cryptoRandomString from 'crypto-random-string'

require('dotenv').config()

const { USERS_API } = process.env

const RAND_OPTS = { length: 20, type: 'base64' }

class UserActionsManager {

    constructor(adminCacheObj) {
        this.cache = adminCacheObj
    }

    _generateAuthHeaders = () => {

        const adminToken = cryptoRandomString(RAND_OPTS)

        this.cache.set(adminToken, true)

        return ({ Authorization: `Bearer ${adminToken}` })
    }

    checkIfUserExists = async spotify_id => {

        const URLWithQuery = 
            USERS_API + 
            `?spotify_id=${spotify_id}`
            + '&limit=1'
            + '&active=true'
	
    
        const headers = this._generateAuthHeaders()

        return axios
            .get(URLWithQuery, { headers })
            .then(({ data }) => data.query_results[0])
    }

    createUser = async newUserData => {

        const headers = this._generateAuthHeaders()

	    return axios
            .post(USERS_API, newUserData, { headers })
            .then(({ data }) => data.new_user)
    }
}

export default UserActionsManager