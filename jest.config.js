module.exports = {
  collectCoverage: true,
  collectCoverageFrom: ['src/**/*.ts'],
  coverageProvider: 'v8',
  coverageReporters: ['text', 'lcov'],
  forceExit: true,
  moduleFileExtensions: ['ts', 'js', 'json'],
  testMatch: ['<rootDir>/test/**/*.spec.ts'],
  testEnvironment: 'node'
};
