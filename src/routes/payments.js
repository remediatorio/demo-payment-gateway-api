const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const config = require('../config');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Encryption utilities for PCI compliance
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

// Encrypt cardholder data
const encryptCardData = (text) => {
  if (!config.encryptionKey) {
    throw new Error('Encryption key not configured');
  }
  
  const key = Buffer.from(config.encryptionKey, 'hex');
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
};

// Decrypt cardholder data
const decryptCardData = (encryptedData) => {
  if (!config.encryptionKey) {
    throw new Error('Encryption key not configured');
  }
  
  const key = Buffer.from(config.encryptionKey, 'hex');
  const parts = encryptedData.split(':');
  
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted data format');
  }
  
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};

// Mask card number for display (PCI DSS compliant)
const maskCardNumber = (cardNumber) => {
  if (!cardNumber || cardNumber.length < 4) {
    return '****';
  }
  const lastFour = cardNumber.slice(-4);
  return '************' + lastFour;
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, config.jwtSecret || process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Authorization middleware for role-based access control
const authorizeRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: 'Access denied: No role assigned' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied: Insufficient permissions' });
    }

    next();
  };
};

// Audit logging function
const auditLog = async (connection, action, userId, details) => {
  try {
    await connection.execute(
      'INSERT INTO audit_logs (action, user_id, details, timestamp) VALUES (?, ?, ?, NOW())',
      [action, userId, JSON.stringify(details)]
    );
  } catch (error) {
    console.error('Audit logging failed:', error);
  }
};

// FIXED: Encrypt card data at rest and use parameterized queries
router.post('/process', async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  if (!cardNumber || !amount || !currency || !merchantId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    // Encrypt card number before storing
    const encryptedCardNumber = encryptCardData(cardNumber);
    
    // Use parameterized query to prevent SQL injection
    const [result] = await connection.execute(
      'INSERT INTO transactions (card_number, amount, currency, merchant_id, status) VALUES (?, ?, ?, ?, ?)',
      [encryptedCardNumber, amount, currency, merchantId, 'pending']
    );
    
    // Return masked card number (PCI compliant)
    res.json({
      transactionId: result.insertId,
      cardNumber: maskCardNumber(cardNumber),
      amount: amount,
      status: 'pending'
    });
  } catch (error) {
    console.error('Transaction processing error:', error);
    res.status(500).json({ error: 'Failed to process transaction' });
  } finally {
    await connection.end();
  }
});

// FIXED: Use parameterized queries to prevent SQL injection
router.get('/search', async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  
  if (!merchantId || !startDate || !endDate) {
    return res.status(400).json({ error: 'Missing required query parameters' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    const [rows] = await connection.execute(
      'SELECT id, amount, currency, merchant_id, status, created_at FROM transactions WHERE merchant_id = ? AND created_at BETWEEN ? AND ?',
      [merchantId, startDate, endDate]
    );
    
    // Return transactions without exposing encrypted card numbers
    res.json({ transactions: rows });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Failed to search transactions' });
  } finally {
    await connection.end();
  }
});

// FIXED: Authentication and authorization required for refund endpoint
router.post('/refund', authenticateToken, authorizeRole(['admin', 'finance']), async (req, res) => {
  const { transactionId, amount } = req.body;
  
  if (!transactionId || !amount) {
    return res.status(400).json({ error: 'Transaction ID and amount are required' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // Verify transaction exists and get current status
    const [transactions] = await connection.execute(
      'SELECT id, status, amount FROM transactions WHERE id = ?',
      [transactionId]
    );

    if (transactions.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const transaction = transactions[0];

    if (transaction.status === 'refunded') {
      return res.status(400).json({ error: 'Transaction already refunded' });
    }

    if (amount > transaction.amount) {
      return res.status(400).json({ error: 'Refund amount exceeds transaction amount' });
    }

    // Process refund with parameterized query
    await connection.execute(
      'UPDATE transactions SET status = ?, refund_amount = ? WHERE id = ?',
      ['refunded', amount, transactionId]
    );

    // Audit log the refund operation
    await auditLog(connection, 'REFUND', req.user.id, {
      transactionId,
      refundAmount: amount,
      originalAmount: transaction.amount,
      userRole: req.user.role
    });

    res.json({ 
      success: true, 
      transactionId, 
      refundAmount: amount 
    });
  } catch (error) {
    console.error('Refund processing error:', error);
    res.status(500).json({ error: 'Failed to process refund' });
  } finally {
    await connection.end();
  }
});

module.exports = router;