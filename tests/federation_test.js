// tests/federation.test.js
const assert = require('assert');
const { FederationService } = require('../src/services/federation');

async function runTests() {
  const env = { DB: { prepare: () => ({ all: async () => ({ results: [] }) }) }, PROXY_URL: 'mock' };
  const fedSvc = new FederationService(env, 'email');

  // Test signature verification
  const payload = { deadlight_version: '1.0', federation_type: 'test', timestamp: new Date().toISOString(), payload: {} };
  payload.signature = await fedSvc.signPayload(payload);
  assert(await fedSvc.verifyFederationSignature(payload), 'Signature verification failed');

  console.log('Tests passed!');
}

runTests().catch(err => console.error('Test failed:', err));
