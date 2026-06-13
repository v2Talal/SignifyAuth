// SignifyAuth Popup v9.0 — Isolated flows, zero errors

var $ = function (s) { return document.querySelector(s); };
var $$ = function (s) { return document.querySelectorAll(s); };

// ── CRYPTO ──
var I = 600000, SL = 32, IL = 12;
function rb(n) { var b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b2a(b) { var s = ''; for (var i = 0; i < new Uint8Array(b).length; i++) s += String.fromCharCode(new Uint8Array(b)[i]); return btoa(s); }
function a2b(a) { var b = atob(a), r = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) r[i] = b.charCodeAt(i); return r; }
function dk(pw, s) { return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']).then(function (m) { return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: s, iterations: I, hash: 'SHA-256' }, m, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); }); }
function enc(pw, d) { var s = rb(SL), iv = rb(IL); return dk(pw, s).then(function (k) { return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, new TextEncoder().encode(d)); }).then(function (e) { var p = new Uint8Array(s.length + iv.length + new Uint8Array(e).length); p.set(s, 0); p.set(iv, s.length); p.set(new Uint8Array(e), s.length + iv.length); return b2a(p); }); }
function dec(e64, pw) { var p = a2b(e64), s = p.slice(0, SL), iv = p.slice(SL, SL + IL), ct = p.slice(SL + IL); return dk(pw, s).then(function (k) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, k, ct); }).then(function (d) { return new TextDecoder().decode(d); }); }
function gkp() { var k = nacl.sign.keyPair(); return { publicKey: b2a(k.publicKey), secretKey: b2a(k.secretKey) }; }
function sgn(sk, m) { var b = a2b(sk), s = nacl.sign.detached(new TextEncoder().encode(m), b); b.fill(0); return b2a(s); }
function vkey(sk) { try { var b = a2b(sk); var ok = b.length === 64; b.fill(0); return ok; } catch (e) { return false; } }
function gpub(sk) { var b = a2b(sk), k = nacl.sign.keyPair.fromSecretKey(b), pk = b2a(k.publicKey); b.fill(0); return pk; }

// ── STORAGE ──
function gK() { return chrome.storage.local.get('signifyauth_keys_v2').then(function (r) { return r.signifyauth_keys_v2 || []; }); }
function sK(k) { return chrome.storage.local.set({ signifyauth_keys_v2: k }); }
function gA() { return chrome.storage.local.get('signifyauth_active_key').then(function (r) { return r.signifyauth_active_key || null; }); }
function sA(id) { return chrome.storage.local.set({ signifyauth_active_key: id }); }

// ── STATE ──
var curReq = null;
var mode = null;
var waitConf = false;
var cache = null;
var cacheT = null;
var selKeyId = null;
var lockedKey = null; // Locks the key for 2-signature flow

function show(v) { $$('.container>div').forEach(function (e) { e.classList.add('hidden'); }); var el = $('#' + v); if (el) { el.classList.remove('hidden'); el.style.animation = 'none'; el.offsetHeight; el.style.animation = ''; } }
function sts(el, m, t) { el.textContent = m; el.className = 'status visible ' + (t || 'info'); }
function clr(el) { el.className = 'status'; el.textContent = ''; }
function toast(m) { var t = document.createElement('div'); t.className = 'toast-msg'; t.textContent = m; document.body.appendChild(t); setTimeout(function () { t.classList.add('show'); }, 10); setTimeout(function () { t.classList.remove('show'); setTimeout(function () { t.remove(); }, 300); }, 2000); }
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function setC(d) { cache = d; clearTimeout(cacheT); cacheT = setTimeout(function () { clrC(); }, 60000); }
function clrC() { if (cache) { cache.secretKey = ''; cache = null; } clearTimeout(cacheT); }
// ── PORT CONNECTION (keeps service worker alive) ──
var port = null;
var portCbs = {};
var portCbId = 0;

function connectPort() {
    try {
        port = chrome.runtime.connect({ name: 'signify-popup' });
        port.onMessage.addListener(function (msg) {
            try { chrome.runtime.lastError; } catch (e) {}
            if (msg._portCbId && portCbs[msg._portCbId]) {
                portCbs[msg._portCbId](msg.data);
                delete portCbs[msg._portCbId];
            }
            // Account selection request from website
            if (msg.type === 'signify-select-key') {
                handleSelectKey(msg);
                return;
            }
            // Incoming sign/create requests from background
            if (msg.type === 'signify-sign-request' && mode !== 'create') {
                handleSign(msg);
            }
            if (msg.type === 'signify-create-key') {
                mode = 'create';
                curReq = { type: 'create-key', requestId: msg._requestId, username: msg.username };
                show('createView');
                $('#newKeyName').value = msg.username || '';
            }
        });
        port.onDisconnect.addListener(function () {
            port = null;
            try { chrome.runtime.lastError; } catch (e) {}
        });
    } catch (e) {}
}

function reply(m) {
    if (port) {
        try { port.postMessage(m); return; } catch (e) {}
    }
    // Fallback
    try {
        var p = chrome.runtime.sendMessage(m, function () {
            try { chrome.runtime.lastError; } catch (e) {}
        });
        if (p && p.catch) p.catch(function () {});
    } catch (e) {}
}

function portSend(msg, cb) {
    if (cb) { portCbId++; portCbs[portCbId] = cb; msg._portCbId = portCbId; }
    if (port) {
        try { port.postMessage(msg); return; } catch (e) {}
    }
    // Fallback
    try {
        var p = chrome.runtime.sendMessage(msg, function (resp) {
            try { chrome.runtime.lastError; } catch (e) {}
            if (cb) cb(resp);
        });
        if (p && p.catch) p.catch(function () { if (cb) cb(null); });
    } catch (e) { if (cb) cb(null); }
}

// ── KEY LIST ──
function renderKeys() {
    return Promise.all([gK(), gA()]).then(function (r) {
        var keys = r[0], aid = r[1], el = $('#keyList');
        if (!keys.length) { el.innerHTML = '<div class="empty"><div class="icon">🔑</div><p>No keys yet</p></div>'; return; }
        el.innerHTML = keys.map(function (k) {
            return '<div class="account-item ' + (k.id === aid ? 'active' : '') + '" data-id="' + k.id + '">' +
                '<div class="account-avatar">' + esc(k.name).charAt(0).toUpperCase() + '</div>' +
                '<div class="account-info"><div class="name">' + esc(k.name) + '</div><div class="id">' + k.publicKey.substring(0, 16) + '…</div></div>' +
                (k.id === aid ? '<span class="check">✓</span>' : '') + '</div>';
        }).join('');
        el.querySelectorAll('.account-item').forEach(function (i) {
            i.addEventListener('click', function () { sA(i.dataset.id).then(renderKeys); });
        });
    });
}

// ── CREATE KEY ──
$('#btnCreateKey').addEventListener('click', function () { mode = 'create'; show('createView'); $('#newKeyName').value = ''; $('#newKeyPassword').value = ''; $('#newKeyPasswordConfirm').value = ''; });
$('#btnBackCreate').addEventListener('click', function () { mode = null; show('mainView'); renderKeys(); });

$('#btnGenerateKey').addEventListener('click', function () {
    var n = $('#newKeyName').value.trim(), p = $('#newKeyPassword').value, p2 = $('#newKeyPasswordConfirm').value;
    if (!n) { toast('Enter a name'); return; }
    if (!p || p.length < 8) { toast('Min 8 characters'); return; }
    if (p !== p2) { toast('Passwords don\'t match'); return; }

    var kp = gkp();
    enc(p, kp.secretKey).then(function (e) {
        var nk = { id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5), name: n, publicKey: kp.publicKey, encryptedSecretKey: e, createdAt: new Date().toISOString() };
        return gK().then(function (ks) { ks.push(nk); return sK(ks); }).then(function () { return sA(nk.id); }).then(function () { return nk; });
    }).then(function (nk) {
        // Register on server
        return registerOnServer(nk.publicKey, nk.name).then(function () { return nk; });
    }).then(function (nk) {
        toast('Key created & registered!');
        var req = curReq;
        mode = null; curReq = null;
        show('mainView'); renderKeys();
        if (req && req.type === 'create-key' && req.requestId) {
            reply({ type: 'signify-create-response', requestId: req.requestId, publicKey: nk.publicKey });
        }
    });
});

// ── ACCOUNT SELECTION (for login) ──
var selectKeyCallback = null;

function handleSelectKey(msg) {
    var requestId = msg._requestId || msg._cid;
    gK().then(function (keys) {
        if (!keys.length) {
            reply({ type: 'signify-select-key-response', _requestId: requestId, selectedPublicKey: null });
            return;
        }

        if (keys.length === 1) {
            reply({ type: 'signify-select-key-response', _requestId: requestId, selectedPublicKey: keys[0].publicKey });
            return;
        }

        mode = 'select';
        var el = $('#accountList');
        el.innerHTML = keys.map(function (k) {
            return '<div class="account-item" data-pub="' + k.publicKey + '">' +
                '<div class="account-avatar">' + esc(k.name).charAt(0).toUpperCase() + '</div>' +
                '<div class="account-info"><div class="name">' + esc(k.name) + '</div><div class="id">' + k.publicKey.substring(0, 16) + '…</div></div>' +
                '</div>';
        }).join('');

        el.querySelectorAll('.account-item').forEach(function (item) {
            item.addEventListener('click', function () {
                var selectedPub = item.dataset.pub;
                mode = null;
                show('mainView');
                renderKeys();
                reply({ type: 'signify-select-key-response', _requestId: requestId, selectedPublicKey: selectedPub });
            });
        });

        show('selectAccountView');
    });
}

// ── SIGN ──
function handleSign(req) {
    if (mode === 'create') return;

    curReq = req;
    mode = 'sign';

    // Confirmation: auto-sign with locked key (no UI needed)
    if (waitConf && lockedKey) {
        waitConf = false;
        doSign(lockedKey.secretKey, lockedKey.publicKey, req, true);
        return;
    }

    gK().then(function (keys) {
        if (!keys.length) { toast('No keys'); return; }

        // ALWAYS show account selection if multiple keys exist
        if (keys.length > 1) {
            renderAccountList(keys, req.requestPublicKey);
            return;
        }

        // Single key — auto-select it
        selKeyId = keys[0].id;

        // If cache has this key, show sign view directly (still need password confirmation)
        if (cache && cache.id === keys[0].id) {
            showSign(keys[0]);
            return;
        }

        showSign(keys[0]);
    });
}

function showSign(key) {
    show('signView');
    $('#signKeyName').textContent = key.name;
    $('#signKeyPub').textContent = key.publicKey.substring(0, 20) + '…';
    $('#signAvatar').textContent = key.name.charAt(0).toUpperCase();
    $('#signPassword').value = '';
    clr($('#signStatus'));
    $('#signPassword').focus();
}

function renderAccountList(keys, requestPublicKey) {
    var el = $('#accountList');
    el.innerHTML = keys.map(function (k) {
        var match = requestPublicKey && k.publicKey === requestPublicKey;
        return '<div class="account-item' + (match ? ' active' : '') + '" data-id="' + k.id + '">' +
            '<div class="account-avatar">' + esc(k.name).charAt(0).toUpperCase() + '</div>' +
            '<div class="account-info"><div class="name">' + esc(k.name) + (match ? ' ✓' : '') + '</div><div class="id">' + k.publicKey.substring(0, 16) + '…</div></div>' +
            '</div>';
    }).join('');
    el.querySelectorAll('.account-item').forEach(function (item) {
        item.addEventListener('click', function () {
            selKeyId = item.dataset.id;
            var key = keys.find(function (k) { return k.id === selKeyId; });
            showSign(key);
        });
    });
    show('selectAccountView');
}

function doSign(sk, pk, req, isConf) {
    var step = isConf ? 'confirmation' : 'identity';
    var sig = sgn(sk, req.challenge);
    reply({ type: 'signify-sign-response', requestId: req.requestId, signature: sig, publicKey: pk, approved: true, step: step });
    if (isConf) {
        clrC(); waitConf = false; mode = null; curReq = null; lockedKey = null;
        toast('Both signatures sent!');
        setTimeout(function () { window.close(); }, 500);
    } else {
        // Lock the key for confirmation — NEVER change it
        lockedKey = { secretKey: sk, publicKey: pk };
        waitConf = true;
        toast('Identity signed! Waiting for confirmation…');
    }
}

$('#btnApproveSign').addEventListener('click', function () {
    if (!curReq || mode !== 'sign') return;
    var pw = $('#signPassword').value, st = $('#signStatus');
    if (!pw) { sts(st, 'Enter password', 'error'); return; }

    // Use the matched key if cached
    if (cache && selKeyId && cache.id === selKeyId) {
        doSign(cache.secretKey, cache.publicKey, curReq, false);
        $('#signPassword').value = '';
        return;
    }

    gK().then(function (keys) {
        // Find the key to use: by selKeyId or by requestPublicKey
        var key = null;
        if (selKeyId) key = keys.find(function (k) { return k.id === selKeyId; });
        if (!key && curReq.requestPublicKey) key = keys.find(function (k) { return k.publicKey === curReq.requestPublicKey; });
        if (!key && keys.length === 1) key = keys[0];
        if (!key) { sts(st, 'No key selected', 'error'); return; }

        return dec(key.encryptedSecretKey, pw).then(function (sk) {
            if (!vkey(sk)) { sts(st, 'Wrong password', 'error'); return; }
            var pk = gpub(sk);
            // Verify this is the key the website asked for
            if (curReq.requestPublicKey && pk !== curReq.requestPublicKey) {
                sts(st, 'Wrong key! This key doesn\'t match the requested account.', 'error');
                return;
            }
            setC({ id: key.id, name: key.name, publicKey: pk, secretKey: sk });
            selKeyId = key.id;
            $('#signPassword').value = '';
            doSign(sk, pk, curReq, false);
        });
    }).catch(function () { sts(st, 'Wrong password', 'error'); });
});

$('#btnRejectSign').addEventListener('click', function () {
    if (curReq && curReq.requestId) reply({ type: 'signify-sign-response', requestId: curReq.requestId, approved: false });
    mode = null; curReq = null; waitConf = false; clrC(); window.close();
});

// ── DECRYPT ──
$('#btnDecryptConfirm').addEventListener('click', function () {
    var pw = $('#decryptPassword').value, st = $('#decryptStatus');
    if (!pw) { sts(st, 'Enter password', 'error'); return; }
    gK().then(function (ks) {
        var k = ks.find(function (x) { return x.id === (curReq._keyId || curReq.keyId); });
        if (!k) { sts(st, 'Key not found', 'error'); return; }
        return dec(k.encryptedSecretKey, pw).then(function (sk) {
            if (!vkey(sk)) { sts(st, 'Wrong password', 'error'); return; }
            var pk = gpub(sk); setC({ id: k.id, name: k.name, publicKey: pk, secretKey: sk });
            if (curReq.type === 'view') { $('#viewKeyContent').textContent = sk; show('viewKeyView'); }
            else if (curReq.challenge) { doSign(sk, pk, curReq, false); }
        });
    }).catch(function () { sts(st, 'Wrong password', 'error'); });
});
$('#btnDecryptCancel').addEventListener('click', function () { mode = null; curReq = null; show('mainView'); renderKeys(); });

// ── VIEW KEY ──
$('#btnCopyViewKey').addEventListener('click', function () { if (cache) navigator.clipboard.writeText(cache.secretKey).then(function () { toast('Copied!'); }); });
$('#btnDownloadViewKey').addEventListener('click', function () {
    if (!cache) return;
    var b = new Blob([JSON.stringify({ type: 'signifyauth-private-key', version: 2, publicKey: cache.publicKey, secretKey: cache.secretKey, name: cache.name }, null, 2)], { type: 'application/json' });
    var a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'signifyauth-key-' + Date.now() + '.json'; a.click();
});
$('#btnCloseViewKey').addEventListener('click', function () { clrC(); $('#viewKeyContent').textContent = ''; show('mainView'); renderKeys(); });

// ── SERVER REGISTRATION ──
var SERVER_URL = 'http://localhost:3000';

function registerOnServer(publicKey, username) {
    return fetch(SERVER_URL + '/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ publicKey: publicKey, username: username })
    }).then(function (r) { return r.json(); }).catch(function () { return { error: 'offline' }; });
}

// ── IMPORT KEY ──
$('#btnImportKey').addEventListener('click', function () {
    var sk = $('#importKeyInput').value.trim(), n = $('#importKeyName').value.trim() || 'Imported', p = $('#importKeyPassword').value, p2 = $('#importKeyPasswordConfirm').value, st = $('#mainStatus');
    if (!sk) { sts(st, 'Paste a key', 'error'); return; }
    if (!vkey(sk)) { sts(st, 'Invalid key', 'error'); return; }
    if (!p || p.length < 8) { sts(st, 'Min 8 characters', 'error'); return; }
    if (p !== p2) { sts(st, 'Passwords don\'t match', 'error'); return; }
    var pk = gpub(sk);
    gK().then(function (ks) {
        if (ks.some(function (k) { return k.publicKey === pk; })) { sts(st, 'Already imported', 'error'); return; }
        return enc(p, sk).then(function (e) {
            var nk = { id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5), name: n, publicKey: pk, encryptedSecretKey: e, createdAt: new Date().toISOString() };
            ks.push(nk); return sK(ks).then(function () { return sA(nk.id); }).then(function () { return nk; });
        });
    }).then(function (nk) {
        if (!nk) return;
        sts(st, 'Imported! Registering on server...', 'info');
        return registerOnServer(nk.publicKey, nk.name).then(function () {
            $('#importKeyInput').value = ''; $('#importKeyName').value = ''; $('#importKeyPassword').value = ''; $('#importKeyPasswordConfirm').value = '';
            sts(st, '✅ Imported & registered!', 'success');
            renderKeys();
        });
    });
});

// ── BACKUP ──
$('#btnBackupKeys').addEventListener('click', function () { show('backupView'); $('#backupPassword').value = ''; $('#backupPasswordConfirm').value = ''; clr($('#backupStatus')); });
$('#btnBackBackup').addEventListener('click', function () { show('mainView'); renderKeys(); });
$('#btnDoBackup').addEventListener('click', function () {
    var pw = $('#backupPassword').value, pw2 = $('#backupPasswordConfirm').value, st = $('#backupStatus');
    if (!pw || pw.length < 8) { sts(st, 'Min 8 characters', 'error'); return; }
    if (pw !== pw2) { sts(st, 'Passwords don\'t match', 'error'); return; }
    gK().then(function (keys) {
        if (!keys.length) { sts(st, 'No keys', 'error'); return; }
        var backup = { type: 'signifyauth-backup', version: 1, keys: keys, createdAt: new Date().toISOString() };
        return enc(pw, JSON.stringify(backup)).then(function (encrypted) {
            var blob = new Blob([JSON.stringify({ type: 'signifyauth-backup-encrypted', version: 1, data: encrypted })], { type: 'application/json' });
            var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'signifyauth-backup-' + new Date().toISOString().split('T')[0] + '.Signify'; a.click();
            sts(st, '✅ Backup saved! ' + keys.length + ' key(s)', 'success'); toast('Backup created!');
        });
    });
});

// ── IMPORT BACKUP ──
$('#btnImportBackup').addEventListener('click', function () { show('importBackupView'); $('#backupFileInput').value = ''; $('#importBackupPassword').value = ''; clr($('#importBackupStatus')); });
$('#btnBackImportBackup').addEventListener('click', function () { show('mainView'); renderKeys(); });
$('#btnDoImportBackup').addEventListener('click', function () {
    var file = $('#backupFileInput').files[0], pw = $('#importBackupPassword').value, st = $('#importBackupStatus');
    if (!file) { sts(st, 'Select a file', 'error'); return; }
    if (!pw) { sts(st, 'Enter password', 'error'); return; }
    var reader = new FileReader();
    reader.onload = function (e) {
        try {
            var bf = JSON.parse(e.target.result);
            if (bf.type !== 'signifyauth-backup-encrypted') { sts(st, 'Invalid file', 'error'); return; }
            dec(bf.data, pw).then(function (d) {
                var backup = JSON.parse(d);
                if (backup.type !== 'signifyauth-backup') { sts(st, 'Wrong password', 'error'); return; }
                return gK().then(function (ek) {
                    var nk = backup.keys.filter(function (bk) { return !ek.some(function (x) { return x.publicKey === bk.publicKey; }); });
                    if (!nk.length) { sts(st, 'All already imported', 'info'); return; }
                    return sK(ek.concat(nk)).then(function () {
                        sts(st, 'Imported ' + nk.length + ' key(s). Registering on server...', 'info');
                        // Register each imported key on the server
                        var chain = Promise.resolve();
                        nk.forEach(function (key) {
                            chain = chain.then(function () {
                                return registerOnServer(key.publicKey, key.name);
                            });
                        });
                        return chain;
                    }).then(function () {
                        sts(st, '✅ Imported & registered!', 'success'); toast('Imported!'); renderKeys();
                    });
                });
            }).catch(function () { sts(st, 'Wrong password', 'error'); });
        } catch (err) { sts(st, 'Invalid file', 'error'); }
    };
    reader.readAsText(file);
});

// ── TOGGLE ──
document.addEventListener('click', function (e) {
    if (e.target.classList.contains('toggle-pw')) { var i = document.getElementById(e.target.dataset.target); if (i) { i.type = i.type === 'password' ? 'text' : 'password'; e.target.textContent = i.type === 'password' ? '👁' : '🙈'; } }
});

// ── MESSAGE (from background via port) ──
// Handled in connectPort's onMessage listener above

// ── INIT ──
connectPort();

setTimeout(function () {
    portSend({ type: 'signify-popup-opened' });
    portSend({ type: 'signify-get-pending' }, function (resp) {
        renderKeys().then(function () {
            if (resp && resp.requests) {
                var ids = Object.keys(resp.requests);
                if (ids.length > 0) {
                    var r = resp.requests[ids[ids.length - 1]];
                    if (r.type === 'signify-create-key') {
                        mode = 'create';
                        curReq = { type: 'create-key', requestId: r._requestId, username: r.username };
                        show('createView');
                        $('#newKeyName').value = r.username || '';
                    } else if (r.type === 'signify-select-key') {
                        handleSelectKey(r);
                    } else if (r.type === 'signify-sign-request') {
                        handleSign(r);
                    }
                }
            }
        });
    });
}, 50);

window.addEventListener('unload', function () {
    reply({ type: 'signify-popup-closed' });
});
