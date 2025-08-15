import { strict as assert } from 'node:assert';
import { FederationService } from '../src/services/federation.js';

async function runTests() {
  const mockDb = {
    prepare: query => ({
      bind: (...params) => ({
        all: async () => ({ results: [] }),
        first: async () => null,
        run: async () => ({ lastRowId: 1 })
      })
    }),
    env: { 
      FEDERATION_PRIVATE_KEY: 'test-key', 
      FEDERATION_PUBLIC_KEY: 'test-key',
      PROXY_URL: 'mock',
      SITE_URL: 'https://deadlight.boo'
    }
  };
  const env = { DB: mockDb, PROXY_URL: 'mock', SITE_URL: 'https://deadlight.boo' };
  const fedSvc = new FederationService(env, 'email');

  // Test signature
  const payload = { 
    deadlight_version: '1.0', 
    federation_type: 'test', 
    timestamp: new Date().toISOString(), 
    payload: {} 
  };
  payload.signature = await fedSvc.signPayload(payload);
  assert(await fedSvc.verifyFederationSignature(payload), 'Signature verification failed');

  // Test queueing
  const queueResult = await fedSvc.queueFederatedPost(1, ['example.com']);
  assert(queueResult.success, 'Queueing failed');

  console.log('Federation tests passed!');
}

runTests().catch(err => console.error('Test failed:', err));