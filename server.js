#!/usr/bin/env node
// Minimal static server for cd-vanilla — not required for offline use
// Serves HTTPS so WebAuthn (YubiKey PRF) works; falls back to HTTP if no cert found.
import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT  = process.env.PORT  || 7801;
const HPORT = process.env.HPORT || 7800; // HTTP redirect port

// Point CERT/KEY at any certificate pair. WebCrypto needs a secure context,
// so HTTPS (or plain localhost) is required for the YubiKey/PRF paths.
const CERT = process.env.CERT || './certs/localhost.crt';
const KEY  = process.env.KEY  || './certs/localhost.key';

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.ico':  'image/x-icon',
};

// The files the demo and its browser test load, and nothing else. This used to
// serve whatever a path named under this directory, which included the default
// TLS key at ./certs/localhost.key. The path is now only ever compared against
// this list, so no request builds a filesystem path: traversal, encoded
// separators and NUL bytes have nothing to act on.
const ALLOWED = new Map([
  ['/',                'index.html'],
  ['/index.html',      'index.html'],
  ['/app.js',          'app.js'],
  ['/app.css',         'app.css'],
  ['/cell-crypto.js',  'cell-crypto.js'],
  ['/tests/test.html', 'tests/test.html'],
]);

function resolveRequest(rawUrl) {
  let urlPath;
  try { urlPath = new URL(rawUrl, 'http://x').pathname; }
  catch { return null; }
  const name = ALLOWED.get(urlPath);
  return name ? path.join(__dirname, name) : null;
}

function handler(req, res) {
  try {
    handleRequest(req, res);
  } catch {
    // Defense in depth: a single unhandled throw here would otherwise take down
    // every request this process serves, not just the bad one.
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad request');
  }
}

function handleRequest(req, res) {
  const filePath = resolveRequest(req.url);
  if (!filePath) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });
}

try {
  const tlsOpts = {
    cert: fs.readFileSync(CERT),
    key:  fs.readFileSync(KEY),
  };
  https.createServer(tlsOpts, handler).listen(PORT, () => {
    console.log(`cd-vanilla → https://localhost:${PORT}`);
  });
  // Redirect HTTP → HTTPS
  http.createServer((req, res) => {
    const host = (req.headers.host || 'localhost').replace(/:\d+$/, '');
    res.writeHead(301, { Location: `https://${host}:${PORT}${req.url}` });
    res.end();
  }).listen(HPORT, () => {
    console.log(`HTTP redirect  → http://localhost:${HPORT} (→ HTTPS)`);
  });
} catch {
  // No cert — plain HTTP fallback (WebAuthn won't work except on localhost)
  http.createServer(handler).listen(PORT, () => {
    console.log(`cd-vanilla → http://localhost:${PORT}  (no TLS — YubiKey PRF disabled)`);
  });
}
