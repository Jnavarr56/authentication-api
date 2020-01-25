export function checkForRequiredVars(requiredVars) {
	let missingRequiredVars = []
	requiredVars.forEach(envVar => {
		if (!process.env[envVar]) {
			missingRequiredVars.push(envVar)
		}
	})
	if (missingRequiredVars.length > 0) {
		console.log(
			'Missing the following ' +
				'environment variables: \n' +
				`${missingRequiredVars.join(', ')}`
		)
		process.exit(1)
	}
}