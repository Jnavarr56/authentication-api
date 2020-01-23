
export function checkForRequiredVars(requiredVars) {
    let missingRequiredVars = []
    Object.keys(requiredVars).forEach(envVar => {
        
        if (requiredVars[envVar] && !process.env[envVar]) {
            missingRequiredVars.push(envVar)
        }
    })
    if (missingRequiredVars.length > 0) {
        console.log(
            'Missing the following '
            + 'environment variables: \n' 
            + `${missingRequiredVars.join(', ')}`
        )
        process.exit(1)
    }
}
