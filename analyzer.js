const IP_ADDRESS = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const MESSAGE_RULES = [
  { id: 'credential-request', category: 'Credential theft', points: 22, pattern: /\b(?:otp|one[- ]time password|verification code|passcode|password|pin|cvv|card number|bank(?:ing)? details|account number|login details?)\b/i, label: 'Credential or payment details are requested.' },
  { id: 'urgency', category: 'Social engineering', points: 12, pattern: /\b(?:urgent|immediately|right away|within \d+ minutes?|act now|last warning|final notice|today only)\b/i, label: 'Pressure-based language pushes immediate action.' },
  { id: 'threat', category: 'Impersonation', points: 18, pattern: /\b(?:account|card|wallet|service|kyc)\s+(?:will be|has been|is being)?\s*(?:suspend(?:ed)?|block(?:ed)?|clos(?:ed|ure)|deactivat(?:ed|ion))\b|\b(?:legal action|arrest warrant|police complaint)\b/i, label: 'A threat of suspension, loss, or legal consequences is used.' },
  { id: 'authority', category: 'Impersonation', points: 14, pattern: /\b(?:bank|government|tax|income tax|customs|police|support|security team|customer care|delivery company|reserve bank|rbi)\b/i, label: 'The sender invokes an authority, bank, or support organization.' },
  { id: 'payment', category: 'Payment fraud', points: 16, pattern: /\b(?:pay|payment|refund|cashback|prize|lottery|fee|transfer|beneficiary|invoice|upi|wallet|collect request|qr code)\b/i, label: 'The message involves money, refunds, UPI, or a payment action.' },
  { id: 'refund-demand', category: 'Payment fraud', points: 22, pattern: /\b(?:refund|cashback)\b[^\n]{0,80}\b(?:fee|pay|payment|upi|transfer)\b/i, label: 'A refund or cashback is conditional on a payment.' },
  { id: 'job-investment', category: 'Job or investment fraud', points: 18, pattern: /\b(?:job|hiring|work from home|salary|recruiter|investment|invest|returns?|profit|crypto|trading|double your money|guaranteed income)\b/i, label: 'An unsolicited job, investment, or unusually profitable offer is described.' },
  { id: 'kyc', category: 'KYC/bank impersonation', points: 20, pattern: /\b(?:kyc|know your customer|pan card|aadhar|aadhaar|bank account)\b/i, label: 'The message uses KYC, identity-document, or bank-account language.' },
  { id: 'action-link', category: 'Credential theft', points: 16, pattern: /\b(?:click|tap|open|visit|use)\b[^.\n]{0,80}\b(?:link|url|website|portal|form)\b|https?:\/\/|www\./i, label: 'The recipient is directed to an online action.' },
];
const COMBINATIONS = [
  { ids: ['authority', 'credential-request'], points: 16, category: 'Credential theft', label: 'Authority impersonation is paired with a request for credentials.' },
  { ids: ['kyc', 'urgency'], points: 14, category: 'KYC/bank impersonation', label: 'KYC or bank language is paired with urgency.' },
  { ids: ['payment', 'urgency'], points: 12, category: 'Payment fraud', label: 'A payment request is paired with pressure to act quickly.' },
  { ids: ['job-investment', 'payment'], points: 14, category: 'Job or investment fraud', label: 'The offer asks for money or a fee.' },
  { ids: ['threat', 'action-link'], points: 12, category: 'Credential theft', label: 'A threat is paired with a link or portal action.' },
];
const KNOWN_BRANDS = ['paypal', 'google', 'microsoft', 'amazon', 'apple', 'netflix', 'whatsapp', 'instagram', 'facebook', 'sbi', 'hdfc', 'icici', 'axisbank'];
const SUSPICIOUS_PATH_WORDS = /(?:login|log-in|signin|sign-in|verify|verification|secure|update|refund|payment|account|wallet|support|claim|kyc|password)/i;
function normalizeObfuscatedText(value) { return value.replace(/\b(?:[a-z0-9]\s+){2,}[a-z0-9]\b/gi, (match) => match.replace(/\s+/g, '')); }
function isValidIpv4(hostname) { return IP_ADDRESS.test(hostname) && hostname.split('.').every((part) => Number(part) <= 255); }
function registrableDomain(hostname) { const labels = hostname.split('.'); return labels.length >= 2 ? labels.slice(-2).join('.') : hostname; }
function evidence(value, match) { return `Evidence: "${(match?.[0] || value).replace(/\s+/g, ' ').slice(0, 100)}"`; }
function parseHttpUrl(raw) {
  const candidate = raw.trim();
  if (!/^https?:\/\//i.test(candidate) || /[\s<>"{}|\\^`]/.test(candidate)) return null;
  try {
    const url = new URL(candidate);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) return null;
    if (url.hostname.includes('..') || (url.hostname !== 'localhost' && !url.hostname.includes('.') && !isValidIpv4(url.hostname))) return null;
    if (isValidIpv4(url.hostname) && url.hostname.split('.').some((part) => Number(part) > 255)) return null;
    return url;
  } catch { return null; }
}
function addMessageIndicator(list, rule, source) { list.push({ id: rule.id, category: rule.category, points: rule.points, text: `${rule.label} ${evidence(source, rule.pattern.exec(source))}` }); }
function analyzeUrl(raw) {
  const url = parseHttpUrl(raw);
  if (!url) return { score: 0, indicators: [], indicatorDetails: [], valid: false, error: 'Enter a valid HTTP or HTTPS URL with a valid hostname.' };
  const details = []; let score = 0; const hostname = url.hostname.toLowerCase(); const labels = hostname.split('.').filter(Boolean); const domain = registrableDomain(hostname);
  const add = (id, category, points, label) => { score += points; details.push({ id, category, points, text: `${label} Evidence: "${`${hostname}${url.pathname}${url.search}`.slice(0, 120)}"` }); };
  if (isValidIpv4(hostname)) add('ip-host', 'Suspicious URL', 30, 'The link uses an IP address instead of a normal domain name.');
  if (hostname.includes('xn--') || /[^\x00-\x7F]/.test(hostname)) add('lookalike-host', 'Suspicious URL', 26, 'The hostname uses internationalized or look-alike characters.');
  if (labels.length > 3) add('misleading-subdomain', 'Suspicious URL', 18, 'Several subdomain levels can hide the real destination.');
  if (url.port && !['80', '443'].includes(url.port)) add('unusual-port', 'Suspicious URL', 12, 'The URL uses an unusual port.');
  if (url.href.length > 140 || url.pathname.length > 80) add('long-structure', 'Suspicious URL', 10, 'The URL has an unusually long path or query string.');
  if (/%(?:25|2f|5c|40)/i.test(url.href)) add('encoded-structure', 'Suspicious URL', 14, 'Encoded characters may obscure the destination.');
  if (SUSPICIOUS_PATH_WORDS.test(`${hostname}${url.pathname}`)) add('suspicious-path', 'Suspicious URL', 10, 'The host or path asks for account, verification, payment, or support action.');
  const URL_SHORTENERS = /^(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|tiny\.cc)$/i;
  if (URL_SHORTENERS.test(domain)) add('url-shortener', 'Suspicious URL', 18, 'The link uses a URL shortener service that obscures the ultimate destination.');
  if (labels.slice(0, -2).some((label) => KNOWN_BRANDS.some((brand) => label.includes(brand))) && !KNOWN_BRANDS.some((brand) => domain.startsWith(`${brand}.`) || domain === `${brand}.com`)) add('brand-lookalike', 'Suspicious URL', 24, 'A trusted brand word appears in a subdomain, not the apparent destination domain.');
  const SUSPICIOUS_TLDS = /\.(?:top|xyz|buzz|fit|work|surf|sbs|monster|rest|click|loan|gq|cf|ml|ga|tk)$/i;
  if (SUSPICIOUS_TLDS.test(domain)) add('suspicious-tld', 'Suspicious URL', 16, 'The domain utilizes a high-risk or commonly abused top-level domain (TLD).');
  if (KNOWN_BRANDS.some((b) => domain.includes(`-${b}`) || domain.includes(`${b}-`)) && !KNOWN_BRANDS.some((b) => domain === `${b}.com`)) add('typosquat-brand', 'Suspicious URL', 24, 'The domain name combines a known brand with hyphens or prefixes/suffixes.');
  if (url.protocol === 'https:') details.push({ id: 'https', category: 'Context', points: 0, text: 'HTTPS is present, but encryption alone does not prove that the destination is legitimate.' });
  else add('no-https', 'Suspicious URL', 10, 'The link does not use HTTPS.');
  return { score, indicators: details.map((item) => item.text), indicatorDetails: details, valid: true, category: 'Suspicious URL' };
}
function riskLevel(score) { return score > 70 ? 'High' : score >= 35 ? 'Medium' : 'Low'; }
function combineModelRisk(type, ruleScore, modelProbability) {
  const mlScore = Math.max(0, Math.min(100, Math.round(modelProbability * 100)));
  if (type !== 'message') return mlScore;
  // The language model is useful as a second opinion, but it is too eager on
  // short, ordinary messages. Keep message-only predictions light unless the
  // transparent rule engine found supporting evidence.
  if (ruleScore === 0) return Math.min(mlScore, 30);
  const blended = Math.round((ruleScore * 0.6) + (mlScore * 0.4));
  return ruleScore < 35 ? Math.min(blended, 34) : blended;
}
function recommendations(level, hasUrl) {
  const common = ['Do not share passwords, OTPs, PINs, or banking details in response to an unsolicited request.', 'Verify the sender through an official app, website, or phone number you find independently.'];
  if (level === 'High') return ['Do not click links, reply, pay, or share information.', ...common, 'Report the content to your bank, provider, platform, or local cybercrime reporting channel.'];
  if (level === 'Medium') return ['Pause and verify the request through an independent official channel.', ...common, ...(hasUrl ? ['Open the official website manually instead of using the supplied link.'] : [])];
  return ['No strong phishing pattern was detected, but treat unexpected requests cautiously.', common[1]];
}
function analyzeMessage(content) {
  const source = normalizeObfuscatedText(content); const details = []; let score = 0; const matched = new Set();
  for (const rule of MESSAGE_RULES) if (rule.pattern.test(source)) { addMessageIndicator(details, rule, source); score += rule.points; matched.add(rule.id); }
  for (const combo of COMBINATIONS) if (combo.ids.every((id) => matched.has(id))) { score += combo.points; details.push({ id: `combo-${combo.ids.join('-')}`, category: combo.category, points: combo.points, text: combo.label }); }
  const categorySignal = details.filter((item) => item.category !== 'Social engineering').sort((a, b) => b.points - a.points)[0];
  return { score, indicators: details.map((item) => item.text), indicatorDetails: details, category: categorySignal?.category || 'No strong pattern detected', hasUrl: false };
}
function analyze(input) {
  if (!input || typeof input !== 'object') throw new TypeError('Request body must be a JSON object.');
  const type = typeof input.type === 'string' ? input.type.toLowerCase() : ''; const content = typeof input.content === 'string' ? input.content.trim() : '';
  if (!['message', 'url'].includes(type)) throw new TypeError('type must be either "message" or "url".');
  if (!content) throw new TypeError('content must be a non-empty string.');
  if (content.length > 10000) throw new RangeError('content must be 10,000 characters or fewer.');
  if (type === 'message' && parseHttpUrl(content) && !/\s/.test(content)) throw new TypeError('Message mode requires message or email text, not a standalone URL.');
  const result = type === 'url' ? analyzeUrl(content) : analyzeMessage(content);
  if (!result.valid && type === 'url') throw new TypeError(result.error);
  const riskScore = Math.max(0, Math.min(100, Math.round(result.score))); const level = riskLevel(riskScore);
  return { type, riskScore, riskLevel: level, scamCategory: result.category, detectedIndicators: result.indicators.length ? result.indicators : ['No strong suspicious indicator was detected by the configured rules.'], indicatorDetails: result.indicatorDetails, recommendedActions: recommendations(level, type === 'url') };
}
module.exports = { analyze, analyzeMessage, analyzeUrl, riskLevel, combineModelRisk, parseHttpUrl, recommendations };
