import axios from 'axios'

require('dotenv').config()

const { GATEWAY_BASE_URL } = process.env

const axiosInstance = axios.create({ baseURL: GATEWAY_BASE_URL })

export default axiosInstance
