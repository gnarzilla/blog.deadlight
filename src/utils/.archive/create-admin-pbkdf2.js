// scripts/create-admin-pbkdf2.js
import crypto from 'crypto';

async function hashPassword(password, options = {}) {
  const encoder = new TextEncoder();
  const iterations = options.iterations || 100000;
  const saltLength = options.saltLength || 16;
  
  const salt = crypto.getRandomValues(new Uint8Array(saltLength));

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
      iterations: iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256 // Length in bits
  );

  // Convert to hex strings
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');

  return { hash: hashHex, salt: saltHex, iterations };
}

// Generate password for "gross-gnar"
const password = 'gross-gnar';
const result = await hashPassword(password);

console.log('Password:', password);
console.log('Hash:', result.hash);
console.log('Salt:', result.salt);
console.log('\nDelete existing admin user:');
console.log(`wrangler d1 execute blog_content_v3 --local --command "DELETE FROM users WHERE username = 'admin'"`);
console.log('\nThen create new admin user:');
console.log(`wrangler d1 execute blog_content_v3 --local --command "INSERT INTO users (username, password, salt, role) VALUES ('admin', '${result.hash}', '${result.salt}', 'admin')"`);
