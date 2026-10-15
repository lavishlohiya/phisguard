const dataset = require('./data/dataset');
const { analyze } = require('./analyzer');

const matrix = { truePositive: 0, trueNegative: 0, falsePositive: 0, falseNegative: 0 };
for (const sample of dataset) {
  const predicted = analyze(sample).riskLevel !== 'Low';
  const actual = sample.label === 'suspicious';
  if (predicted && actual) matrix.truePositive += 1;
  else if (!predicted && !actual) matrix.trueNegative += 1;
  else if (predicted) matrix.falsePositive += 1;
  else matrix.falseNegative += 1;
}
const precision = matrix.truePositive / (matrix.truePositive + matrix.falsePositive || 1);
const recall = matrix.truePositive / (matrix.truePositive + matrix.falseNegative || 1);
const f1 = 2 * precision * recall / (precision + recall || 1);
const falsePositiveRate = matrix.falsePositive / (matrix.falsePositive + matrix.trueNegative || 1);
console.log(JSON.stringify({ samples: dataset.length, precision, recall, f1, falsePositiveRate, confusionMatrix: matrix }, null, 2));
