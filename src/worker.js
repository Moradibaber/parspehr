// parspehr password gate: nothing is served until the correct login is given.
async function sha256(text) {
  const data = new TextEncoder().encode(text);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function isAllowed(request, env) {
  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Basic ')) return false;
  let decoded = '';
  try {
    decoded = atob(header.slice(6));
  } catch (e) {
    return false;
  }
  const i = decoded.indexOf(':');
  if (i < 0) return false;
  const user = decoded.slice(0, i);
  const pass = decoded.slice(i + 1);
  const userOk = sameBytes(await sha256(user), await sha256(env.SITE_USER));
  const passOk = sameBytes(await sha256(pass), await sha256(env.SITE_PASSWORD));
  return userOk && passOk;
}

export default {
  async fetch(request, env) {
    if (!env.SITE_USER || !env.SITE_PASSWORD) {
      return new Response('Site is not configured yet.', { status: 500 });
    }
    if (!(await isAllowed(request, env))) {
      return new Response('Login required', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="parspehr", charset="UTF-8"',
          'Cache-Control': 'no-store'
        }
      });
    }
    const res = await env.ASSETS.fetch(request);
    const out = new Response(res.body, res);
    out.headers.set('Cache-Control', 'no-store');
    out.headers.set('X-Robots-Tag', 'noindex, nofollow');
    return out;
  }
};
