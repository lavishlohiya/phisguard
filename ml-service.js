const { spawn } = require('node:child_process');
const readline = require('node:readline');

class PhishingModel {
  constructor() {
    this.pending = [];
    this.failed = false;
    this.process = spawn(process.env.PYTHON_BIN || 'python', ['-u', 'model.py'], { cwd: __dirname, stdio: ['pipe', 'pipe', 'pipe'] });
    readline.createInterface({ input: this.process.stdout }).on('line', (line) => this.resolveNext(line));
    this.process.on('error', (error) => this.fail(error));
    this.process.on('exit', (code) => { if (code !== 0) this.fail(new Error(`Python model exited with code ${code}.`)); });
    this.process.stderr.on('data', (chunk) => process.stderr.write(`[phisguard-model] ${chunk}`));
  }
  resolveNext(line) {
    const request = this.pending.shift(); if (!request) return;
    try { const result = JSON.parse(line); result.error ? request.reject(new Error(result.error)) : request.resolve(result); }
    catch (error) { request.reject(error); }
  }
  fail(error) { this.failed = true; while (this.pending.length) this.pending.shift().reject(error); }
  predict(input, type) {
    if (this.failed || this.process.exitCode !== null) return Promise.reject(new Error('Phishing model is unavailable.'));
    const payload = typeof input === 'object' && input !== null ? input : { text: input, type };
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.process.stdin.write(`${JSON.stringify(payload)}\n`, (error) => { if (error) this.fail(error); });
    });
  }
}
module.exports = { PhishingModel };
