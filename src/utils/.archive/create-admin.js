# Use this Node.js script to generate the correct password hash and salt
// create-admin.js
import { hashPassword } from './lib.deadlight/core/src/auth/password.js';

async function createAdmin() {
  const password = 'gross-gnar';
  const { hash, salt } = await hashPassword(password);
  
  console.log(`Hash: ${hash}`);
  console.log(`Salt: ${salt}`);
  
  console.log('\nRun this command:');
  console.log(`wrangler d1 execute blog_content_v3 --local --command "INSERT INTO users (username, password, salt, role) VALUES ('admin', '${hash}', '${salt}', 'admin')"`);
}

createAdmin().catch(console.error);
