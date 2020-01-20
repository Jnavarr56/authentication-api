import { Schema, model } from 'mongoose'

const tokenDataSchema = new Schema({
    refresh_token: {
        type: String,
        required: true
    },
    access_token: {
        type: String,
        required: true
    },
}, { timestamps: true })

export default model('TokenData', tokenDataSchema, 'TokenData')