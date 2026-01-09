// src/utils/utils.js

export function parseCookies(cookieHeader) {
  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return {};
  }
  
  return cookieHeader.split(';').reduce((acc, cookie) => {
    const [key, ...valueParts] = cookie.trim().split('=');
    if (key) {  
      acc[key] = valueParts.join('=');
    }
    return acc;
  }, {});
}

export function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

