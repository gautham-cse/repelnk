require('dotenv').config();
const fetch = require('node-fetch');

module.exports = async function (req, res) {
  const apiKey = process.env.API_KEY;
  const urlToCheck = req.payload.url;

  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const requestBody = {
    client: {
      clientId: 'replnk-client',
      clientVersion: '1.0',
    },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
      platformTypes: ['WINDOWS'],
      threatEntryTypes: ['URL'],
      threatEntries: [
        {
          url: urlToCheck,
        },
      ],
    },
  };

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody),
    });
    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      return res.status(200).json({ isPhishing: true });
    } else {
      return res.status(200).json({ isPhishing: false });
    }
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
};
