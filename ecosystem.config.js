module.exports = {
  apps: [
    {
      name: 'super-split',
      script: 'server.js',
      env: { NODE_ENV: 'production', PORT: 3001 },
      max_memory_restart: '300M',
    },
    {
      name: 'super-split-staging',
      script: 'server.js',
      env: { NODE_ENV: 'production', PORT: 3002, RUN_JOBS: 'false' },
      max_memory_restart: '300M',
    },
  ],
};
