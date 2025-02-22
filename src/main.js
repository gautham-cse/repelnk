import dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

export default async function (req, res) {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  const apiKey = process.env.API_KEY;

  const endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
  const requestBody = {
    client: {
      clientId: "repelnk-client-engine",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [
        { url }
      ]
    }
  };

  try {
    const response = await fetch(`${endpoint}?key=${apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      return res.status(200).json({ isSafe: false });
    } else {
      return res.status(200).json({ isSafe: true });
    }
  } catch (error) {
    return res.status(500).json({ error: 'Error verifying URL' });
  }
}
