import { Schema, model } from 'mongoose'

const tokenDataSchema = new Schema(
	{
		refresh_token: {
			type: String,
			required: true
		},
		access_token: {
			type: String,
			required: true
		},
		expires_at: {
			type: Date,
			required: true
		},
		spotify_id: {
			type: String,
			required: true
		},
		user_id: {
			type: Schema.Types.ObjectId,
			ref: 'User',
			required: true
		}
	},
	{ timestamps: true }
)

export default model('TokenData', tokenDataSchema, 'TokenData')
