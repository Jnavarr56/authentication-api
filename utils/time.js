import moment from 'moment'

export function getSecsTillFuture(timeVal, timeUnit) {
	const today = moment()
	const tomorrow = moment()
		.add(timeVal, timeUnit)
		.startOf(timeUnit)
	return tomorrow.diff(today, 'seconds')
}

export function getExpiresAtDate(secs) {
	return moment()
		.add(secs, 'seconds')
		.toDate()
}
export function isTokenExpired(expiresAt) {
	return new Date() > expiresAt
}
