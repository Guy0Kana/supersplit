'use strict';
const express = require('express');
const meter = require('../jobs/meter');
const router = express.Router();

router.get('/', (req, res) => {
  res.json({ ok: true, ...meter.getCached() });
});

module.exports = router;
