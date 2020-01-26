import axios from '../axios-config/axios'
import { getSecsTillFuture } from '../time'

class TokenStoreManager {

    constructor({ model, cache }) {
        this.cache = cache
        this.model = model
    }

    storeTokenData = async tokenData => {

        const {
            user_id,
            spotify_id, 
            expires_at,
            access_token,
            refresh_token
        } = tokenData
        
        const dbSaveSuccessful = await this.model
            .create({
                user_id,
                spotify_id, 
                expires_at,
                access_token,
                refresh_token
            }).then(newTokenData => newTokenData)
    
        if (!dbSaveSuccessful) return null
    
        this.cache.set(
            access_token,
            {
                user_id,
                expires_at,
                spotify_id, 
                refresh_token
            },
            getSecsTillFuture(1, 'day')
        )
    }
    
    retrieveTokenData = async accessToken => {
        
        const inCache = this.cache.get(accessToken)
        if (inCache) return inCache
    
        
        return await this.model
            .findOne({ access_token: accessToken })
            .sort({ createdAt: -1 })
            .then(tokenData => tokenData)
    }
}

export default TokenStoreManager

