module.exports = {
  database: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'SuperSecret123!',
    name: process.env.DB_NAME || 'payments'
  },
  jwtSecret: 'my-super-secret-jwt-key-12345',
  stripeApiKey: 'stripe_live_key_EXAMPLE_1234567890abcdef',
  encryptionKey: 'aes-256-hardcoded-key-do-not-use',
  adminPassword: 'admin123',
  apiPort: process.env.PORT || 3000
};
