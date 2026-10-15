const express = require('express');
const path = require('path');
const { analyze, analyzeMessage, analyzeUrl, recommendations, riskLevel, combineModelRisk } = require('./analyzer');
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
    const rawInput = req.body;
    const type = typeof rawInput?.type === 'string' ? rawInput.type.toLowerCase() : '';
    const content = typeof rawInput?.content === 'string' ? rawInput.content.trim() : '';
    if (!['message', 'url'].includes(type)) throw new TypeError('type must be either "message" or "url".');
    if (!content) throw new TypeError('content must be a non-empty string.');
    if (content.length > 10000) throw new RangeError('content must be 10,000 characters or fewer.');
    if (type === 'url' && !analyzeUrl(content).valid) throw new TypeError('Enter a valid HTTP or HTTPS URL with a valid hostname.');

    // Pretrained Model Evaluation
    let prediction = null;
    let mlError = null;
    try {
      prediction = await phishingModel.predict({ text: content, type });
    } catch (err) {
      mlError = err.message;
    }

    let result;
    if (prediction && !prediction.error) {
      const phishProb = typeof prediction.phish_probability === 'number' ? prediction.phish_probability : (prediction.suspicious ? 1.0 : 0.0);
      const ruleResult = type === 'message' ? analyzeMessage(content) : analyzeUrl(content);
      const riskScore = type === 'url' && ruleResult.verifiedDomain ? ruleResult.score : combineModelRisk(type, ruleResult?.score || 0, phishProb);
      const level = riskLevel(riskScore);
      const isPhish = prediction.suspicious && riskScore >= 35;
      const category = isPhish ? (type === 'url' ? 'Phishing URL detected by machine learning' : 'Phishing email/message detected by rule/model analysis') : (type === 'url' ? 'Legitimate URL' : 'Legitimate message');
      
      const detectedIndicators = isPhish
        ? [`Pretrained DistilBERT model classified this ${type} as suspicious/phishing with ${Math.round((prediction.confidence || phishProb) * 100)}% confidence.`]
        : [`Pretrained DistilBERT model found no phishing signatures (${Math.round((prediction.confidence || (1 - phishProb)) * 100)}% safe confidence).`];

      result = {
        type,
        riskScore,
        riskLevel: level,
        scamCategory: category,
        detectedIndicators: type === 'url' ? [...new Set([...ruleResult.indicators, ...detectedIndicators])] : detectedIndicators,
        indicatorDetails: type === 'url' ? [...ruleResult.indicatorDetails, {
          id: 'ml-distilbert',
          category: 'Machine Learning',
          points: riskScore,
          text: detectedIndicators[0],
        }] : [{
          id: 'ml-distilbert', category: isPhish ? 'Machine Learning' : 'Safe Pattern', points: riskScore, text: detectedIndicators[0],
        }],
        recommendedActions: recommendations(level, type === 'url'),
        modelPrediction: {
          available: true,
          label: prediction.label,
          confidence: prediction.confidence,
          suspicious: prediction.suspicious,
          phish_probability: prediction.phish_probability,
          engine: prediction.engine || 'URL ML model'
        }
      };
    } else {
      // Fallback to rule engine if model is temporarily loading or unavailable
      result = analyze(req.body);
      result.modelPrediction = { available: false, error: mlError || 'Model unavailable' };
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
        const type = typeof item?.type === 'string' ? item.type.toLowerCase() : '';
        const content = typeof item?.content === 'string' ? item.content.trim() : '';
        if (!['message', 'url'].includes(type) || !content) {
          throw new TypeError('Each batch item must have valid type ("message"|"url") and non-empty content.');
        }
        if (type === 'url' && !analyzeUrl(content).valid) throw new TypeError('Enter a valid HTTP or HTTPS URL with a valid hostname.');

        let pred = null;
        try { pred = await phishingModel.predict({ text: content, type }); } catch { /* ignore */ }

        let resObj;
        if (pred && !pred.error) {
          const phishProb = typeof pred.phish_probability === 'number' ? pred.phish_probability : (pred.suspicious ? 1.0 : 0.0);
          const ruleResult = type === 'message' ? analyzeMessage(content) : analyzeUrl(content);
          const riskScore = type === 'url' && ruleResult.verifiedDomain ? ruleResult.score : combineModelRisk(type, ruleResult?.score || 0, phishProb);
          const level = riskLevel(riskScore);
          const isPhish = pred.suspicious && riskScore >= 35;
          const category = isPhish
            ? (type === 'url' ? 'Phishing link detected by DistilBERT' : 'Phishing email/message detected by DistilBERT')
            : (type === 'url' ? 'Legitimate URL' : 'Legitimate message');
          resObj = {
            type,
            riskScore,
            riskLevel: level,
            scamCategory: category,
            detectedIndicators: [
              `Pretrained DistilBERT model classified this ${type} with ${Math.round((pred.confidence || phishProb) * 100)}% confidence.`
            ],
            recommendedActions: recommendations(level, type === 'url'),
            modelPrediction: {
              available: true,
              label: pred.label,
              confidence: pred.confidence,
              suspicious: pred.suspicious,
            engine: pred.engine || 'URL ML model'
            }
          };
        } else {
          resObj = analyze(item);
        }

        results.push({ success: true, input: (item.content || '').slice(0, 80), ...resObj });
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
