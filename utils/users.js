import axios from 'axios'

require('dotenv').config()

const { GATEWAY_URL: baseURL, USERS_API } = process.env

const axiosInstance = axios.create({ baseURL })

export async function checkIfUserExists(spotify_id) {
	const query = `?spotify_id=${spotify_id}` + '&limit=1' + '&active=true'

	return await axiosInstance
		.get(USERS_API + query)
		.then(({ data }) => data.query_results[0])
		.catch(error => {
			console.log(error)
			return null
		})
}

export async function createUser(newUserData) {
	return await axiosInstance
		.post(USERS_API, newUserData)
		.then(({ data }) => data.new_user)
		.catch(error => {
			console.log(error)
			return null
		})
}
