module.exports = {
	parser: 'babel-eslint',
	extends: ['eslint:recommended', 'plugin:json/recommended', 'prettier'],
	plugins: ['json'],
	parserOptions: {
		ecmaVersion: 2018,
		sourceType: 'module',
		ecmaFeatures: {
			jsx: true
		}
	},
	rules: {
		'comma-dangle': ['warn', 'never'],
		'object-curly-spacing': ['warn', 'always'],
		'array-bracket-spacing': ['warn', 'always'],
		'comma-spacing': ['warn', { before: false, after: true }],
		'space-in-parens': ['warn', 'never'],
		'array-element-newline': ['warn', 'consistent'],
		'object-curly-newline': ['warn', { consistent: true }],
		'no-unused-vars': ['off'],
		'no-unused-vars': ['off']
	},
	env: {
		node: true,
		es6: true
	}
}
