const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const cors = require('cors');
const config = require('./config');
const paymentRoutes = require('./routes/payments');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');

const app = express();

// VULNERABILITY: Overly permissive CORS
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// Enforce HTTPS with HSTS header
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});

// Redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    next();
  } else {
    res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
});

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

// TLS configuration with strong cipher suites
const tlsOptions = {
  key: fs.readFileSync(config.tlsKeyPath || './certs/private-key.pem'),
  cert: fs.readFileSync(config.tlsCertPath || './certs/certificate.pem'),
  ca: config.tlsCaPath ? fs.readFileSync(config.tlsCaPath) : undefined,
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',
  ciphers: [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384'
  ].join(':'),
  honorCipherOrder: true,
  secureOptions: require('constants').SSL_OP_NO_SSLv3 | 
                 require('constants').SSL_OP_NO_TLSv1 | 
                 require('constants').SSL_OP_NO_TLSv1_1
};

// Create HTTPS server
const httpsServer = https.createServer(tlsOptions, app);

httpsServer.listen(config.apiPort, () => {
  console.log(`Payment Gateway API running securely on port ${config.apiPort}`);
});

// Create HTTP server for redirecting to HTTPS
const httpServer = http.createServer(app);
const httpPort = config.httpPort || 80;

httpServer.listen(httpPort, () => {
  console.log(`HTTP server running on port ${httpPort} (redirecting to HTTPS)`);
});