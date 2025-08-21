// ESM Node helper for password hashing
import { hashPassword } from '../../../lib.deadlight/core/src/auth/password.js';

const password = process.argv[2];
if (!password) {
  console.error("Usage: node hash-password.mjs <password>");
  process.exit(1);
}

hashPassword(password).then(({ hash, salt }) => {
  console.log(`${hash} ${salt}`);
});
