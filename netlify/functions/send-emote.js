// netlify/functions/send-emote.js
// ⚡ ENHANCED VERSION - SUPER FAST API PROXY

exports.handler = async (event, context) => {
  const startTime = Date.now();

  // ✅ Quick method check
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const params = event.queryStringParameters;

    // ✅ Fast validation with single condition
    if (!params?.server || !params?.tc || !params?.uid1 || !params?.emote_id) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: 'Missing required parameters',
          required: ['server', 'tc', 'uid1', 'emote_id']
        })
      };
    }

    // ✅ Optimized URL building - Clean trailing slash from server URL
    const cleanServerUrl = params.server.replace(/\/$/, '');
    const urlParts = [`${cleanServerUrl}/join?tc=${encodeURIComponent(params.tc)}`];

    // Add UIDs efficiently (up to 5)
    for (let i = 1; i <= 5; i++) {
      if (params[`uid${i}`]) {
        urlParts.push(`uid${i}=${encodeURIComponent(params[`uid${i}`])}`);
      }
    }

    urlParts.push(`emote_id=${encodeURIComponent(params.emote_id)}`);

    // Ensure the Server URL points to the webhook endpoint if not already
    // The bot listens on /invite
    let targetUrl = params.server;
    if (!targetUrl.endsWith('/invite')) {
      // Handle trailing slash
      if (targetUrl.endsWith('/')) {
        targetUrl = targetUrl + 'invite';
      } else {
        targetUrl = targetUrl + '/invite';
      }
    }

    console.log(`⚡ API Call: Sending POST to Bot: ${targetUrl}`, payload);

    const response = await fetch(targetUrl, {
      method: "POST", // Changed from GET to POST
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Netlify-Proxy"
      },
      body: JSON.stringify(payload), // Send JSON body
      signal: controller.signal
    });

    clearTimeout(timeout);

    // Retrieve response text
    const data = await response.text();
    // const headers = {}; // Not used in the final return, so commenting out
    // response.headers.forEach((val, key) => { headers[key] = val; }); // Not used

    const elapsed = Date.now() - startTime;

    console.log(`✅ Response in ${elapsed}ms - Status: ${response.status}`);

    // If json, try to parse
    let parsedData = data;
    try {
      parsedData = JSON.parse(data);
    } catch (e) {
      // ignore
    }

    return {
      statusCode: 200, // Return 200 even on error to prevent frontend crash, but with success: false
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Cache-Control': 'no-cache'
      },
      body: JSON.stringify({
        success: response.ok,
        status: response.status,
        elapsed: elapsed,
        message: response.ok ? "Emote Request Sent to Bot" : "Bot Error",
        data: parsedData
      })
    };

  } catch (error) {
    const elapsed = Date.now() - startTime;

    console.error(`❌ Error after ${elapsed}ms:`, error.message);

    // ✅ Handle timeout specifically
    const isTimeout = error.name === 'AbortError';

    return {
      statusCode: isTimeout ? 504 : 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        success: false,
        error: isTimeout ? 'Request timeout (8s)' : error.message,
        elapsed: elapsed
      })
    };
  }
};