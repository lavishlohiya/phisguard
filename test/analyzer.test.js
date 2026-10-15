const test = require('node:test');
const assert = require('node:assert/strict');
const { analyze, combineModelRisk, parseHttpUrl } = require('../analyzer');
test('scores a normal informational message as low risk', () => { const result = analyze({ type: 'message', content: 'Hi, dinner is at 7pm. See you there!' }); assert.equal(result.riskLevel, 'Low'); assert.ok(result.riskScore < 30); });
test('combines signals instead of relying on one keyword', () => { const oneKeyword = analyze({ type: 'message', content: 'Your OTP is 123456.' }); const scam = analyze({ type: 'message', content: 'Urgent: your bank account will be suspended. Verify your OTP and PIN immediately at http://192.168.1.5/login?verify=true' }); assert.ok(oneKeyword.riskScore < 60); assert.equal(scam.riskLevel, 'High'); assert.ok(scam.detectedIndicators.length >= 3); });
test('detects credential requests with letters spaced apart', () => { const result = analyze({ type: 'message', content: 'give me your o t p for b a n k credentials, give me ur o t p' }); assert.ok(result.riskScore > 0); assert.equal(result.riskLevel, 'Medium'); assert.match(result.detectedIndicators.join(' '), /password, OTP|bank/i); });
test('inspects URL structure without fetching it', () => { const result = analyze({ type: 'url', content: 'https://paypal.secure-login.example.com/account/verify' }); assert.equal(result.riskLevel, 'Medium'); assert.match(result.detectedIndicators.join(' '), /subdomain|account|verification/i); });
test('treats HTTPS as a signal rather than proof of safety', () => { const result = analyze({ type: 'url', content: 'https://example.com' }); assert.match(result.detectedIndicators.join(' '), /HTTPS is present/); assert.equal(result.riskLevel, 'Low'); });
test('validates input', () => { assert.throws(() => analyze({ type: 'email', content: 'hello' }), /type must be either/); assert.throws(() => analyze({ type: 'url', content: '' }), /non-empty/); });
test('rejects plain text, malformed URLs, and unsupported protocols without scoring', () => {
  for (const content of ['hello world', 'https://', 'ftp://example.com', 'https://bad host.example']) {
    assert.throws(() => analyze({ type: 'url', content }), /valid HTTP or HTTPS URL/);
  }
});
test('rejects a standalone URL in message mode', () => {
  assert.throws(() => analyze({ type: 'message', content: 'https://example.com' }), /message or email text/);
});
test('does not apply URL structure rules to message mode', () => {
  const result = analyze({ type: 'message', content: 'Please review https://paypal.secure-login.example.com/account/verify when convenient.' });
  assert.equal(result.indicatorDetails.some((item) => item.id === 'ip-host' || item.id === 'misleading-subdomain'), false);
});
test('returns category, evidence, and safe actions for common scam families', () => {
  for (const [content, category] of [
    ['Urgent: your bank KYC will be suspended. Verify your OTP immediately.', 'Credential theft'],
    ['Your UPI refund is pending. Pay a small fee now to receive the refund.', 'Payment fraud'],
    ['Guaranteed work from home job, pay the registration fee today.', 'Job or investment fraud'],
  ]) {
    const result = analyze({ type: 'message', content });
    assert.ok(['Medium', 'High'].includes(result.riskLevel)); assert.equal(result.scamCategory, category);
    assert.ok(result.detectedIndicators.some((item) => item.includes('Evidence:'))); assert.ok(result.recommendedActions.length >= 2);
  }
});
test('handles legitimate and borderline messages conservatively', () => {
  assert.equal(analyze({ type: 'message', content: 'Your OTP is 123456.' }).riskLevel, 'Low');
  assert.equal(analyze({ type: 'message', content: 'Your order will arrive tomorrow. Track it in the official app.' }).riskLevel, 'Low');
  assert.equal(analyze({ type: 'message', content: 'hi' }).riskLevel, 'Low');
  assert.equal(analyze({ type: 'message', content: 'i love you' }).riskLevel, 'Low');
  assert.equal(analyze({ type: 'message', content: 'event' }).riskLevel, 'Low');
});
test('flags URL shortener services that obscure the destination', () => {
  const result = analyze({ type: 'url', content: 'https://bit.ly/bank-verification-token' });
  assert.ok(result.indicatorDetails.some((item) => item.id === 'url-shortener'));
});
test('keeps model-only false positives in the light message band', () => {
  assert.equal(combineModelRisk('message', 0, 0.99), 30);
  assert.equal(combineModelRisk('message', 22, 0.99), 34);
});
test('allows high message risk only when rules support the model', () => {
  assert.ok(combineModelRisk('message', 100, 0.9) > 70);
});
test('normalizes equivalent Amazon URL forms consistently', () => {
  const urls = ['https://www.amazon.in', 'https://www.amazon.in/', 'www.amazon.in', 'amazon.in'];
  const scores = urls.map((content) => analyze({ type: 'url', content }).riskScore);
  assert.ok(scores.every((score) => score === scores[0]));
  assert.equal(scores[0], 0);
  assert.equal(parseHttpUrl(' http://www.amazon.in/ ').hostname, 'www.amazon.in');
});
test('adds HTTPS internally when a URL has no scheme', () => {
  const bare = analyze({ type: 'url', content: 'paypa1.com/login' });
  const explicit = analyze({ type: 'url', content: 'https://paypa1.com/login' });
  assert.equal(parseHttpUrl('paypa1.com/login').protocol, 'https:');
  assert.equal(bare.riskLevel, explicit.riskLevel);
  assert.ok(bare.riskScore > 0);
});
test('does not trust deceptive or merely unfamiliar domains', () => {
  assert.ok(analyze({ type: 'url', content: 'https://amazon.in.evil.com' }).riskScore > 0);
  assert.ok(analyze({ type: 'url', content: 'https://amaz0n.in' }).riskScore > 0);
  assert.equal(analyze({ type: 'url', content: 'https://example-unfamiliar.test' }).riskLevel, 'Low');
});
test('keeps meaningful URL indicators', () => {
  assert.ok(analyze({ type: 'url', content: 'http://192.168.1.5/login' }).indicatorDetails.some((item) => item.id === 'ip-host'));
  assert.ok(analyze({ type: 'url', content: 'https://paypal.secure-login.example.com/account/verify' }).riskScore > 0);
});
test('detects lookalikes across brands without treating one brand as special', () => {
  for (const content of ['https://paypa1.com/login', 'https://micros0ft-support.com/verify', 'https://secure-binance.com/account']) {
    const result = analyze({ type: 'url', content });
    assert.ok(result.riskScore > 0);
    assert.ok(result.indicatorDetails.some((item) => ['typosquat-brand', 'similar-brand-domain', 'brand-lookalike'].includes(item.id)));
  }
});
test('keeps an unfamiliar but structurally ordinary domain low risk', () => {
  const result = analyze({ type: 'url', content: 'https://unfamiliar-example-domain.test' });
  assert.equal(result.riskLevel, 'Low');
});

