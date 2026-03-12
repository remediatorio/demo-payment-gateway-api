module.exports = {
  database: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    name: process.env.DB_NAME || 'payments'
  },
  jwtSecret: process.env.JWT_SECRET,
  stripeApiKey: process.env.STRIPE_API_KEY,
  encryptionKey: process.env.ENCRYPTION_KEY,
  adminPassword: process.env.ADMIN_PASSWORD,
  apiPort: process.env.PORT || 3000
};