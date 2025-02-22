import dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

export default async function (req, res) {
  console.log('Request received:', req);
  console.log('Response object:', res);

  if (!req || !res) {
    return console.error('Request or Response object is undefined');
  }

  const { query } = req;

  if (!query || !query.url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  const { url } = query;
  const apiKey = process.env.GOOGLE_API_KEY;
  const appwriteUrl = process.env.APPWRITE_URL;

  const endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
  const requestBody = {
    client: {
      clientId: "your-project-id",
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
    console.error('Error verifying URL:', error);
    return res.status(500).json({ error: 'Error verifying URL' });
  }
}
