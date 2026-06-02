module.exports = {
  database: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'SuperSecret123!',
    name: process.env.DB_NAME || 'payments'
  },
  jwtSecret: process.env.JWT_SECRET || 'my-super-secret-jwt-key-12345',
  stripeApiKey: process.env.STRIPE_API_KEY || 'stripe_live_key_EXAMPLE_1234567890abcdef',
  encryptionKey: process.env.ENCRYPTION_KEY || 'aes-256-hardcoded-key-do-not-use',
  apiPort: process.env.PORT || 3000
};