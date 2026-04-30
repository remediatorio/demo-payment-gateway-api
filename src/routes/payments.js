const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const config = require('../config');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

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

// Card tokenization function - generates a secure token for card storage
const tokenizeCardNumber = (cardNumber) => {
  const encryptionKey = process.env.CARD_ENCRYPTION_KEY || config.cardEncryptionKey;
  
  if (!encryptionKey) {
    throw new Error('Card encryption key not configured');
  }
  
  const cipher = crypto.createCipher('aes-256-cbc', encryptionKey);
  let encrypted = cipher.update(cardNumber, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted;
};

// Extract last 4 digits for display purposes
const getLastFourDigits = (cardNumber) => {
  if (!cardNumber || cardNumber.length < 4) {
    return '****';
  }
  return cardNumber.slice(-4);
};

// Validate card number format
const validateCardNumber = (cardNumber) => {
  if (!cardNumber) {
    return false;
  }
  
  const sanitized = cardNumber.replace(/\s+/g, '');
  
  if (!/^\d{13,19}$/.test(sanitized)) {
    return false;
  }
  
  return true;
};

// FIXED: PCI-DSS compliant payment processing with tokenization
router.post('/process', async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  if (!validateCardNumber(cardNumber)) {
    return res.status(400).json({ error: 'Invalid card number format' });
  }
  
  if (!amount || !currency || !merchantId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    const sanitizedCardNumber = cardNumber.replace(/\s+/g, '');
    const cardToken = tokenizeCardNumber(sanitizedCardNumber);
    const lastFourDigits = getLastFourDigits(sanitizedCardNumber);
    
    const [result] = await connection.execute(
      'INSERT INTO transactions (card_token, last_four_digits, amount, currency, merchant_id, status) VALUES (?, ?, ?, ?, ?, ?)',
      [cardToken, lastFourDigits, amount, currency, merchantId, 'pending']
    );
    
    res.json({
      transactionId: result.insertId,
      cardLastFour: lastFourDigits,
      amount: amount,
      currency: currency,
      status: 'pending'
    });
  } catch (error) {
    console.error('Payment processing error:', error);
    res.status(500).json({ error: 'Failed to process payment' });
  } finally {
    await connection.end();
  }
});

// FIXED: SQL Injection protection with parameterized queries
router.get('/search', async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  
  if (!merchantId || !startDate || !endDate) {
    return res.status(400).json({ error: 'Missing required query parameters' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    const [rows] = await connection.execute(
      'SELECT id, last_four_digits, amount, currency, merchant_id, status, created_at FROM transactions WHERE merchant_id = ? AND created_at BETWEEN ? AND ?',
      [merchantId, startDate, endDate]
    );
    
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