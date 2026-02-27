const express = require('express');
const cors = require('cors');
const config = require('./config');
const paymentRoutes = require('./routes/payments');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');

const app = express();

// VULNERABILITY: Overly permissive CORS
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

app.use('/api/payments', paymentRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);

// VULNERABILITY: Verbose error messages exposing internals
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    config: config.database
  });
});

app.listen(config.apiPort, () => {
  console.log(`PAYMENT GATEWAY API RUNNING ON PORT ${config.apiPort}`);
});