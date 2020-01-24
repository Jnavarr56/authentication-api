import axios from 'axios'

require('dotenv').config()

const { USERS_API } = process.env

export async function checkIfUserExists(spotify_id) {
	const query = { spotify_id, limit: 1, active: true }

	return await axios
		.get(USERS_API, query)
		.then(({ data }) => data.query_results[0])
		.catch(error => {
			console.log(error)
			return null
		})
}

export async function createUser(newUserData) {
	return await axios
		.post(USERS_API, newUserData)
		.then(({ data }) => data.new_user)
		.catch(error => {
			console.log(error)
			return null
		})
}
