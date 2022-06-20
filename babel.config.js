module.exports = (api) => {
  const env = api.env();

  api.cache(() => env);

  return {
    presets: ['@babel/preset-env', '@babel/preset-typescript'],
    plugins: [
      [
        '@babel/plugin-transform-runtime',
        {
          corejs: 3
        }
      ]
    ]
  };
};
