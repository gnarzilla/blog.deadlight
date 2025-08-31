// src/utils/auth.js
import { verifyJWT } from '../utils/jwt.js';

export async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Import the password as a key
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Use PBKDF2 to derive the key
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256 // Length in bits
  );

  // Convert to hex strings
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');

  return { hash: hashHex, salt: saltHex };
}

export async function verifyPassword(password, storedHash, storedSalt) {
  const encoder = new TextEncoder();
  const salt = Uint8Array.from(
    storedSalt.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );

  // Import the password as a key
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Use PBKDF2 to derive the key
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256 // Length in bits
  );

  // Convert to hex string for comparison
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return hashHex === storedHash;
}

export async function checkAuth(request, env) {
  const cookies = request.headers.get('Cookie') || '';
  const token = cookies.split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('token='))
    ?.split('=')[1];
  
  if (!token) {
    return null;
  }

  return await verifyJWT(token, env.JWT_SECRET);
}