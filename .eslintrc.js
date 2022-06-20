module.exports = {
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/eslint-plugin/recommended',
    'plugin:import/recommended',
    'plugin:jest/recommended'
  ],
  env: {
    amd: true,
    browser: true,
    node: true
  },
  globals: {
    'jest/globals': true,
    module: true,
    process: true,
    window: true
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaFeatures: {
      experimentalObjectRestSpread: true,
      experimentalDecorators: true,
      legacyDecorators: true,
      jsx: true
    },
    sourceType: 'module'
  },
  rules: {
    'import/no-anonymous-default-export': 'off',
    'jest/no-conditional-expect': 'off',
    'jest/no-disabled-tests': 'warn',
    'jest/no-focused-tests': 'error',
    'jest/no-identical-title': 'error',
    'jest/no-try-expect': 'off',
    'jest/prefer-to-have-length': 'warn',
    'jest/valid-expect': 'error',
    'no-useless-escape': 'warn',
    'no-unused-vars': 'off',
    '@typescript-eslint/ban-ts-comment': 'warn',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-empty-function': 'warn',
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': ['error', { ignoreRestSiblings: true }],
    '@typescript-eslint/no-var-requires': 'off'
  },
  settings: {
    react: {
      version: '16.14'
    },
    'import/resolver': {
      typescript: {} // this loads <rootdir>/tsconfig.json to eslint
    }
  }
};
