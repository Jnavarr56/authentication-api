import cryptoRandomString from 'crypto-random-string'
import { encryptWithPassword, decryptWithPassword } from '../encryption'
import { getSecsTillFuture } from '../time'

// Must be 256 bits (32 characters)
const RAND_OPTS = { length: 32, type: 'base64' }

class StateParamManager {

    constructor(cacheObj) {
        this.cache = cacheObj
    }

    /*
        Produce a state param string encrypted with a password
        and set it in cache for 1 day. 
    */
    generateEncryptedStateParam = () => {

        const stateParam = cryptoRandomString(RAND_OPTS)
        const password = cryptoRandomString(RAND_OPTS)

        const encryptedStateParam = encryptWithPassword(stateParam, password)

        this.cache.set(
            encryptedStateParam,
            {
                stateParam,
                password
            },
            getSecsTillFuture(1, 'day')
        )
        
        return encryptedStateParam
    }

    /*
        Validate an encrypted state param by checking 
        for presence in cache and attempting to decrypt
        using password. If successful return true, else
        false or null.
    */
    validateEncryptedStateParam = stateParamEncrypted => {

        const stateParamInCache = this.cache.get(stateParamEncrypted)

        if (!stateParamInCache)
            return false
    
        this.cache.del(stateParamEncrypted)
        const { password, stateParam } = stateParamInCache
    
        const stateParamDecrypted = decryptWithPassword(stateParamEncrypted, password)   

        if (stateParamDecrypted !== stateParam) throw new Error('STATE PARAM UNCRECOGNIZED')
    }

}

export default StateParamManager