import moment from 'moment'

export function getTimeTillTomorrow(timeUnit) {
	const today = moment()
	const tomorrow = moment()
		.add(1, 'day')
		.startOf('day')
	return tomorrow.diff(today, timeUnit)
}

export function getExpiresAtDate(secs) {
	return moment()
		.add(secs, 'seconds')
		.toDate()
}
export function isTokenExpired(expiresAt) {
	return new Date() > expiresAt
}
