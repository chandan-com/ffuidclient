const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = process.env.FT_API_KEY;
const API_ID = process.env.FT_API_ID;

app.post('/api/check-uid', async (req, res) => {
  const { uid } = req.body;

  if (!uid) {
    return res.json({ message: 'UID is required' });
  }

  const payload = { user_id: uid, validation_code: 'freefire_bd' };
  const bodyJson = JSON.stringify(payload); // no extra spaces, matches Python's separators=(',', ':')

  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = uuidv4();
  const bodyHash = crypto.createHash('sha256').update(bodyJson).digest('hex');
  const canonicalString = `POST\n/api/reseller/v2/check-id\n${timestamp}\n${nonce}\n${bodyHash}`;
  const signature = crypto
    .createHmac('sha256', API_KEY)
    .update(canonicalString)
    .digest('hex');

  const headers = {
    'Content-Type': 'application/json',
    'X-FT-API-ID': API_ID,
    'X-FT-Timestamp': timestamp,
    'X-FT-Nonce': nonce,
    'X-FT-Signature': signature,
    'X-FT-Sandbox': 'false',
  };

  try {
    const response = await axios.post(
      'https://api.flashtopup.com/api/reseller/v2/check-id',
      bodyJson,
      { headers, timeout: 7000 }
    );
    const ftData = response.data;

    // console.log('DEBUG: API Response from FlashTopup:', ftData);

    if (ftData.success) {
      return res.json({ username: ftData.data.account_name ,
        region : ftData.data.region
      });
    } else {
      const errorMsg = ftData.error?.message || 'Unknown Error';
      return res.json({ message: errorMsg });
    }
  } catch (err) {
    console.error('FULL ERROR:', err.message);
    console.error('RESPONSE DATA:', err.response?.data);
    console.error('STATUS:', err.response?.status);
    if (err.code === 'ECONNABORTED') {
      return res.json({ valid: false, message: 'Server took too long. Please try again.' });
    }
    return res.json({ valid: false, message: err.message, debug: err.response?.data || null });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
