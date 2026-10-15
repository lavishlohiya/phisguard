const express = require('express');
const path = require('path');
const { analyze, recommendations } = require('./analyzer');
const { PhishingModel } = require('./ml-service');

const app = express();
const PORT = process.env.PORT || 3000;
const publicDirectory = path.join(__dirname, 'public');
const scanHistory = [];
const phishingModel = new PhishingModel();

app.use(express.json());
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  return next();
});
app.use(express.static(publicDirectory));

app.post('/api/analyze', async (req, res) => {
  try {
    const result = analyze(req.body);
    if (result.type === 'message') {
      try {
        const prediction = await phishingModel.predict(req.body.content);
        const label = prediction.label.toLowerCase();
        const mlFlagged = /phish|scam|fraud|malicious|spam|label[_ -]?[13]\b/.test(label);
        const text = (req.body.content || '').trim();
        const wordCount = text.split(/\s+/).filter(Boolean).length;
        const hasRuleIndicators = (result.indicatorDetails && result.indicatorDetails.length > 0) || result.riskScore > 0;
        const hasPhishSyntax = /https?:\/\/|\.com\b|\.xyz\b|\.top\b|\.net\b|urgent|account|verify|otp|login|password|kyc|bank/i.test(text);
        
        // Corroborate ML signal: require rule corroboration or sufficient length + suspicious keywords
        // to avoid high false positives on casual, short greetings/text ("hi", "i love you", "event")
        const suspicious = mlFlagged && (hasRuleIndicators || (wordCount >= 5 && text.length >= 80 && hasPhishSyntax));
        
        result.modelPrediction = { label: prediction.label, confidence: prediction.confidence, suspicious };
        if (suspicious) {
          result.riskScore = Math.max(result.riskScore, Math.round(prediction.confidence * 100));
          result.riskLevel = result.riskScore >= 60 ? 'High' : result.riskScore >= 30 ? 'Medium' : 'Low';
          result.recommendedActions = recommendations(result.riskLevel, false);
          result.detectedIndicators.push(`ML model classified this message as phishing (${Math.round(prediction.confidence * 100)}% confidence).`);
        }
      } catch (modelError) { result.modelPrediction = { available: false, error: modelError.message }; }
    }
    scanHistory.unshift({
      id: `${Date.now()}-${scanHistory.length}`,
      type: result.type,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      scamCategory: result.scamCategory,
      detectedIndicators: result.detectedIndicators,
      createdAt: new Date().toISOString(),
    });
    if (scanHistory.length > 50) scanHistory.pop();
    res.json(result);
  }
  catch (error) { res.status(error instanceof RangeError ? 413 : 400).json({ error: error.message }); }
});

app.post('/api/batch-analyze', async (req, res) => {
  try {
    const { items } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'items must be a non-empty array of objects { type, content }.' });
    }
    if (items.length > 25) {
      return res.status(400).json({ error: 'Batch limit is 25 items per request.' });
    }
    const results = [];
    for (const item of items) {
      try {
        const resObj = analyze(item);
        if (resObj.type === 'message') {
          try {
            const pred = await phishingModel.predict(item.content);
            const label = pred.label.toLowerCase();
            const mlFlagged = /phish|scam|fraud|malicious|spam|label[_ -]?[13]\b/.test(label);
            const text = (item.content || '').trim();
            const wordCount = text.split(/\s+/).filter(Boolean).length;
            const hasRuleIndicators = (resObj.indicatorDetails && resObj.indicatorDetails.length > 0) || resObj.riskScore > 0;
            const hasPhishSyntax = /https?:\/\/|\.com\b|\.xyz\b|\.top\b|\.net\b|urgent|account|verify|otp|login|password|kyc|bank/i.test(text);
            const susp = mlFlagged && (hasRuleIndicators || (wordCount >= 5 && text.length >= 80 && hasPhishSyntax));

            resObj.modelPrediction = { label: pred.label, confidence: pred.confidence, suspicious: susp };
            if (susp) {
              resObj.riskScore = Math.max(resObj.riskScore, Math.round(pred.confidence * 100));
              resObj.riskLevel = resObj.riskScore >= 60 ? 'High' : resObj.riskScore >= 30 ? 'Medium' : 'Low';
              resObj.recommendedActions = recommendations(resObj.riskLevel, false);
            }
          } catch { /* ml optional */ }
        }
        results.push({ success: true, input: item.content.slice(0, 80), ...resObj });
        scanHistory.unshift({
          id: `${Date.now()}-${scanHistory.length}`,
          type: resObj.type,
          riskScore: resObj.riskScore,
          riskLevel: resObj.riskLevel,
          scamCategory: resObj.scamCategory,
          detectedIndicators: resObj.detectedIndicators,
          createdAt: new Date().toISOString(),
        });
        if (scanHistory.length > 50) scanHistory.pop();
      } catch (err) {
        results.push({ success: false, input: (item?.content || '').slice(0, 80), error: err.message });
      }
    }
    res.json({ count: results.length, results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dashboard', (req, res) => {
  const counts = { High: 0, Medium: 0, Low: 0 };
  scanHistory.forEach((scan) => { counts[scan.riskLevel] += 1; });
  res.json({
    totalScans: scanHistory.length,
    riskCounts: counts,
    recentScans: scanHistory.slice(0, 10),
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'phisguard-api',
    timestamp: new Date().toISOString(),
  });
});

app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && error.status === 400 && error.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Request body must contain valid JSON.' });
  }
  return next(error);
});

app.use((req, res) => {
  res.sendFile(path.join(publicDirectory, 'index.html'));
});

if (require.main === module) app.listen(PORT, () => console.log(`PhishGuard is running at http://localhost:${PORT}`));

module.exports = app;
