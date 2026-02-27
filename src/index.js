const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const https = require('https');
const http = require('http');
const fs = require('fs');
const config = require('./config');
const paymentRoutes = require('./routes/payments');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');

const app = express();

// Security headers with HSTS
app.use(helmet({
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    return next();
  }
  res.redirect(301, `https://${req.headers.host}${req.url}`);
});

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

// HTTPS server configuration
const httpsOptions = {
  key: fs.readFileSync(config.ssl.keyPath || './certs/private-key.pem'),
  cert: fs.readFileSync(config.ssl.certPath || './certs/certificate.pem'),
  ca: config.ssl.caPath ? fs.readFileSync(config.ssl.caPath) : undefined,
  secureProtocol: 'TLSv1_2_method',
  ciphers: [
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-GCM-SHA384'
  ].join(':'),
  honorCipherOrder: true,
  secureOptions: require('constants').SSL_OP_NO_SSLv2 | 
                 require('constants').SSL_OP_NO_SSLv3 | 
                 require('constants').SSL_OP_NO_TLSv1 |
                 require('constants').SSL_OP_NO_TLSv1_1
};

// Create HTTPS server
const httpsServer = https.createServer(httpsOptions, app);

httpsServer.listen(config.apiPort, () => {
  console.log(`Payment Gateway API running securely on HTTPS port ${config.apiPort}`);
});

// Create HTTP server for redirects only
const httpServer = http.createServer(app);
const httpPort = config.httpPort || 80;

httpServer.listen(httpPort, () => {
  console.log(`HTTP server running on port ${httpPort} (redirecting to HTTPS)`);
});