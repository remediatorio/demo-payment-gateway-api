const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const config = require('../config');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Encryption configuration for PCI compliance
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || config.encryptionKey;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

// Encrypt card number using AES-256-GCM
const encryptCardNumber = (cardNumber) => {
  if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
    throw new Error('Invalid encryption key. Must be 64 hex characters (32 bytes).');
  }
  
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  
  let encrypted = cipher.update(cardNumber, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
};

// Decrypt card number
const decryptCardNumber = (encryptedData, iv, authTag) => {
  const decipher = crypto.createDecipheriv(
    ENCRYPTION_ALGORITHM,
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    Buffer.from(iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};

// Mask card number for display (show only last 4 digits)
const maskCardNumber = (cardNumber) => {
  if (!cardNumber || cardNumber.length < 4) {
    return '****';
  }
  return '**** **** **** ' + cardNumber.slice(-4);
};

// Get last 4 digits of card
const getLastFourDigits = (cardNumber) => {
  if (!cardNumber || cardNumber.length < 4) {
    return '';
  }
  return cardNumber.slice(-4);
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

// FIXED: PCI-compliant payment processing with encrypted storage
router.post('/process', async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  if (!cardNumber || !amount || !currency || !merchantId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    // Encrypt the full card number
    const { encrypted, iv, authTag } = encryptCardNumber(cardNumber);
    
    // Store only last 4 digits for display purposes
    const lastFourDigits = getLastFourDigits(cardNumber);
    
    // Use parameterized query to prevent SQL injection
    const query = `INSERT INTO transactions (card_number_encrypted, card_number_iv, card_number_auth_tag, card_last_four, amount, currency, merchant_id, status) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    
    const [result] = await connection.execute(query, [
      encrypted,
      iv,
      authTag,
      lastFourDigits,
      amount,
      currency,
      merchantId,
      'pending'
    ]);
    
    // Return masked card number only
    res.json({
      transactionId: result.insertId,
      cardNumber: maskCardNumber(cardNumber),
      amount: amount,
      status: 'pending'
    });
  } catch (error) {
    console.error('Payment processing error:', error);
    res.status(500).json({ error: 'Failed to process payment' });
  } finally {
    await connection.end();
  }
});

// FIXED: SQL Injection prevention with parameterized queries
router.get('/search', async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  
  if (!merchantId || !startDate || !endDate) {
    return res.status(400).json({ error: 'Missing required query parameters' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    const query = "SELECT id, card_last_four, amount, currency, merchant_id, status, created_at FROM transactions WHERE merchant_id = ? AND created_at BETWEEN ? AND ?";
    
    const [rows] = await connection.execute(query, [merchantId, startDate, endDate]);
    
    // Return transactions with masked card numbers only
    const sanitizedRows = rows.map(row => ({
      ...row,
      cardNumber: row.card_last_four ? '**** **** **** ' + row.card_last_four : '****'
    }));
    
    res.json({ transactions: sanitizedRows });
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