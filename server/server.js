const express = require('express');
const cors = require('cors');
const nacl = require('tweetnacl');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '1kb' }));
app.use(express.static(path.join(__dirname, '..', 'demo-site')));
app.use('/sdk', express.static(path.join(__dirname, '..', 'sdk')));

// In-memory stores
const users = new Map();
const challenges = new Map();
const activeSessions = new Map();

// Periodic cleanup every 5 minutes
setInterval(function () {
    var now = Date.now();
    for (var [id, ch] of challenges) {
        if (now - ch.createdAt > 5 * 60 * 1000) challenges.delete(id);
    }
    for (var [token, sess] of activeSessions) {
        if (now > sess.expiresAt) activeSessions.delete(token);
    }
}, 5 * 60 * 1000);

function generateChallenge() {
    return crypto.randomBytes(32).toString('base64');
}

function generateNonce() {
    return crypto.randomBytes(16).toString('hex');
}

function sanitizeString(str, maxLen) {
    if (typeof str !== 'string') return '';
    return str.substring(0, maxLen).replace(/[<>"'&]/g, '');
}

function safeVerify(messageBytes, signatureBytes, publicKeyBytes) {
    try {
        if (publicKeyBytes.length !== 32) return false;
        if (signatureBytes.length !== 64) return false;
        return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    } catch (e) {
        return false;
    }
}

// Rate limiter (simple in-memory)
const rateLimits = new Map();
function checkRateLimit(ip, action, maxRequests, windowMs) {
    var key = ip + ':' + action;
    var now = Date.now();
    var entry = rateLimits.get(key);
    if (!entry || now - entry.start > windowMs) {
        rateLimits.set(key, { start: now, count: 1 });
        return true;
    }
    entry.count++;
    return entry.count <= maxRequests;
}
setInterval(function () {
    var now = Date.now();
    for (var [key, entry] of rateLimits) {
        if (now - entry.start > 60000) rateLimits.delete(key);
    }
}, 60000);

// ============================================================
//  POST /api/register
// ============================================================
app.post('/api/register', function (req, res) {
    var ip = req.ip;
    if (!checkRateLimit(ip, 'register', 10, 60000)) {
        return res.status(429).json({ error: 'Too many requests. Try again later.' });
    }

    var publicKey = req.body.publicKey;
    var username = req.body.username;

    if (!publicKey || typeof publicKey !== 'string') {
        return res.status(400).json({ error: 'Public key is required' });
    }

    publicKey = publicKey.trim();
    if (publicKey.length < 30 || publicKey.length > 100) {
        return res.status(400).json({ error: 'Invalid public key format' });
    }

    var pkBytes;
    try {
        pkBytes = Buffer.from(publicKey, 'base64');
    } catch (e) {
        return res.status(400).json({ error: 'Invalid base64 encoding' });
    }
    if (pkBytes.length !== 32) {
        return res.status(400).json({ error: 'Public key must be 32 bytes' });
    }

    username = sanitizeString(username, 30) || 'User';

    for (var [id, user] of users) {
        if (user.publicKey === publicKey) {
            return res.json({ userId: id, message: 'Already registered' });
        }
    }

    var userId = uuidv4();
    users.set(userId, {
        publicKey: publicKey,
        username: username,
        createdAt: new Date().toISOString()
    });

    res.json({ userId: userId, message: 'Registration successful' });
});

// ============================================================
//  POST /api/challenge
// ============================================================
app.post('/api/challenge', function (req, res) {
    var ip = req.ip;
    if (!checkRateLimit(ip, 'challenge', 30, 60000)) {
        return res.status(429).json({ error: 'Too many requests.' });
    }

    var publicKey = req.body.publicKey;
    if (!publicKey || typeof publicKey !== 'string') {
        return res.status(400).json({ error: 'Public key is required' });
    }

    var userId = null;
    for (var [id, user] of users) {
        if (user.publicKey === publicKey) {
            userId = id;
            break;
        }
    }

    if (!userId) {
        return res.status(404).json({ error: 'User not found. Please register first.' });
    }

    var challenge = generateChallenge();
    var nonce = generateNonce();
    var timestamp = Date.now();
    var sessionId = uuidv4();

    challenges.set(sessionId, {
        challenge: challenge,
        nonce: nonce,
        timestamp: timestamp,
        userId: userId,
        publicKey: publicKey,
        createdAt: Date.now(),
        step: 'identity',
        identitySignature: null,
        used: false
    });

    res.json({
        sessionId: sessionId,
        challenge: challenge,
        nonce: nonce,
        timestamp: timestamp,
        step: 'identity',
        message: 'Sign this challenge to prove your identity'
    });
});

// ============================================================
//  POST /api/verify-identity — Step 1
// ============================================================
app.post('/api/verify-identity', function (req, res) {
    var ip = req.ip;
    if (!checkRateLimit(ip, 'verify', 30, 60000)) {
        return res.status(429).json({ error: 'Too many requests.' });
    }

    var sessionId = req.body.sessionId;
    var signature = req.body.signature;
    var publicKey = req.body.publicKey;

    if (!sessionId || !signature || !publicKey) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    var challengeData = challenges.get(sessionId);
    if (!challengeData) {
        return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    if (challengeData.used) {
        challenges.delete(sessionId);
        return res.status(400).json({ error: 'Challenge already used' });
    }

    if (challengeData.step !== 'identity') {
        return res.status(400).json({ error: 'Invalid step' });
    }

    if (challengeData.publicKey !== publicKey) {
        return res.status(400).json({ error: 'Public key mismatch' });
    }

    var elapsed = Date.now() - challengeData.timestamp;
    if (elapsed > 5 * 60 * 1000) {
        challenges.delete(sessionId);
        return res.status(400).json({ error: 'Challenge expired' });
    }

    var messageBytes = new TextEncoder().encode(challengeData.challenge);
    var signatureBytes, publicKeyBytes;
    try {
        signatureBytes = Buffer.from(signature, 'base64');
        publicKeyBytes = Buffer.from(publicKey, 'base64');
    } catch (e) {
        return res.status(400).json({ error: 'Invalid encoding' });
    }

    if (!safeVerify(messageBytes, signatureBytes, publicKeyBytes)) {
        return res.status(401).json({ error: 'Invalid identity signature' });
    }

    challengeData.identitySignature = signature;
    challengeData.step = 'confirmation';
    challengeData.timestamp = Date.now();

    var confirmationChallenge = generateChallenge();
    challengeData.confirmationChallenge = confirmationChallenge;

    res.json({
        sessionId: sessionId,
        confirmationChallenge: confirmationChallenge,
        step: 'confirmation',
        message: 'Identity verified. Sign the confirmation challenge.'
    });
});

// ============================================================
//  POST /api/verify-confirmation — Step 2
// ============================================================
app.post('/api/verify-confirmation', function (req, res) {
    var ip = req.ip;
    if (!checkRateLimit(ip, 'verify', 30, 60000)) {
        return res.status(429).json({ error: 'Too many requests.' });
    }

    var sessionId = req.body.sessionId;
    var signature = req.body.signature;
    var publicKey = req.body.publicKey;

    if (!sessionId || !signature || !publicKey) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    var challengeData = challenges.get(sessionId);
    if (!challengeData) {
        return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    if (challengeData.used) {
        challenges.delete(sessionId);
        return res.status(400).json({ error: 'Challenge already used' });
    }

    if (challengeData.step !== 'confirmation') {
        return res.status(400).json({ error: 'Invalid step. Complete identity verification first.' });
    }

    if (challengeData.publicKey !== publicKey) {
        return res.status(400).json({ error: 'Public key mismatch' });
    }

    var elapsed = Date.now() - challengeData.timestamp;
    if (elapsed > 5 * 60 * 1000) {
        challenges.delete(sessionId);
        return res.status(400).json({ error: 'Challenge expired' });
    }

    var messageBytes = new TextEncoder().encode(challengeData.confirmationChallenge);
    var signatureBytes, publicKeyBytes;
    try {
        signatureBytes = Buffer.from(signature, 'base64');
        publicKeyBytes = Buffer.from(publicKey, 'base64');
    } catch (e) {
        return res.status(400).json({ error: 'Invalid encoding' });
    }

    if (!safeVerify(messageBytes, signatureBytes, publicKeyBytes)) {
        return res.status(401).json({ error: 'Invalid confirmation signature' });
    }

    challengeData.used = true;

    var sessionToken = uuidv4();
    activeSessions.set(sessionToken, {
        userId: challengeData.userId,
        publicKey: publicKey,
        createdAt: Date.now(),
        expiresAt: Date.now() + 24 * 60 * 60 * 1000
    });

    var user = users.get(challengeData.userId);

    res.json({
        success: true,
        sessionToken: sessionToken,
        userId: challengeData.userId,
        username: user ? user.username : 'Unknown',
        message: 'Authentication successful — both signatures verified'
    });
});

// ============================================================
//  POST /api/verify-session
// ============================================================
app.post('/api/verify-session', function (req, res) {
    var sessionToken = req.body.sessionToken;
    if (!sessionToken) {
        return res.status(400).json({ error: 'Session token required' });
    }

    var session = activeSessions.get(sessionToken);
    if (!session) {
        return res.status(401).json({ error: 'Invalid session' });
    }

    if (Date.now() > session.expiresAt) {
        activeSessions.delete(sessionToken);
        return res.status(401).json({ error: 'Session expired' });
    }

    var user = users.get(session.userId);
    res.json({
        valid: true,
        userId: session.userId,
        username: user ? user.username : 'Unknown'
    });
});

// ============================================================
//  POST /api/logout
// ============================================================
app.post('/api/logout', function (req, res) {
    var sessionToken = req.body.sessionToken;
    if (sessionToken) {
        activeSessions.delete(sessionToken);
    }
    res.json({ success: true, message: 'Logged out' });
});

// ============================================================
//  GET /api/user/:userId
// ============================================================
app.get('/api/user/:userId', function (req, res) {
    var user = users.get(req.params.userId);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    res.json({
        userId: req.params.userId,
        username: user.username,
        createdAt: user.createdAt
    });
});

// SPA fallback
app.get('*', function (req, res) {
    res.sendFile(path.join(__dirname, '..', 'demo-site', 'index.html'));
});

// Global error handler
app.use(function (err, req, res, next) {
    console.error('[SignifyAuth] Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, function () {
    console.log('\n  🔐 SignifyAuth Server running on http://localhost:' + PORT);
    console.log('  📡 API endpoints:');
    console.log('     POST /api/register            - Register with public key');
    console.log('     POST /api/challenge            - Request login challenge');
    console.log('     POST /api/verify-identity      - Step 1: Identity signature');
    console.log('     POST /api/verify-confirmation  - Step 2: Session confirmation');
    console.log('     POST /api/verify-session       - Check session validity');
    console.log('     POST /api/logout               - End session\n');
});
