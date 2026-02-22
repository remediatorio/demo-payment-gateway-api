const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const config = require('../config');

// VULNERABILITY: SQL Injection - card number passed directly into query
router.post('/process', async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  const connection = await mysql.createConnection(config.database);
  
  // VULNERABILITY: Storing full card number (PCI violation)
  const query = `INSERT INTO transactions (card_number, amount, currency, merchant_id, status) 
                 VALUES ('${cardNumber}', ${amount}, '${currency}', '${merchantId}', 'pending')`;
  
  try {
    const [result] = await connection.execute(query);
    
    // VULNERABILITY: Returning full card number in response
    res.json({
      transactionId: result.insertId,
      cardNumber: cardNumber,
      amount: amount,
      status: 'pending'
    });
  } catch (error) {
    res.status(500).json({ error: error.message, query: query });
  }
});

// VULNERABILITY: SQL Injection in search
router.get('/search', async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  const connection = await mysql.createConnection(config.database);
  
  const query = "SELECT * FROM transactions WHERE merchant_id = '" + merchantId + 
                "' AND created_at BETWEEN '" + startDate + "' AND '" + endDate + "'";
  
  const [rows] = await connection.execute(query);
  res.json({ transactions: rows });
});

// VULNERABILITY: No authentication on refund endpoint
router.post('/refund', async (req, res) => {
  const { transactionId, amount } = req.body;
  const connection = await mysql.createConnection(config.database);
  
  await connection.execute(
    `UPDATE transactions SET status = 'refunded', refund_amount = ${amount} WHERE id = ${transactionId}`
  );
  
  res.json({ success: true, transactionId, refundAmount: amount });
});

module.exports = router;
