// Content Script v10.0 — Bulletproof connection, zero errors

(function () {
    'use strict';

    var ID = '__sa_v10__';
    if (window[ID]) return;
    window[ID] = true;

    var ORIGIN = window.location.origin;
    var port = null;
    var q = [];
    var cbs = {};
    var cid = 0;
    var indicator = null;
    var alive = false;

    function connect() {
        if (alive) return;
        try {
            port = chrome.runtime.connect({ name: 'signify' });
            alive = true;
            port.onMessage.addListener(onMsg);
            port.onDisconnect.addListener(function () {
                alive = false;
                port = null;
                try { chrome.runtime.lastError; } catch (e) {}
                setTimeout(connect, 200);
            });
            while (q.length) { safePost(q.shift()); }
        } catch (e) {
            alive = false;
            setTimeout(connect, 300);
        }
    }

    function safePost(msg) {
        if (port && alive) {
            try { port.postMessage(msg); return; } catch (e) { alive = false; }
        }
        // One-shot fallback
        try {
            chrome.runtime.sendMessage(msg, function () {
                try { chrome.runtime.lastError; } catch (e) {}
            });
        } catch (e) {}
    }

    function onMsg(msg) {
        try { chrome.runtime.lastError; } catch (e) {}

        if (msg._cid && cbs[msg._cid]) {
            cbs[msg._cid](msg.data);
            delete cbs[msg._cid];
            return;
        }

        if (msg.type === 'signify-sign-response') {
            post({ _signifyResponse: true, _requestId: msg.requestId, available: true,
                approved: msg.approved, step: msg.step,
                identitySignature: msg.step === 'identity' ? msg.signature : undefined,
                confirmationSignature: msg.step === 'confirmation' ? msg.signature : undefined,
                publicKey: msg.publicKey });
            hideIndicator();
        }

        if (msg.type === 'signify-create-response') {
            post({ _signifyResponse: true, _requestId: msg.requestId, available: true,
                created: true, publicKey: msg.publicKey });
            hideIndicator();
        }

        if (msg.type === 'signify-select-key-response') {
            // Relay back to website via _signifyResponse
            post({ _signifyResponse: true, _requestId: msg._requestId || 'select-key',
                available: true, selectedPublicKey: msg.selectedPublicKey });
            hideIndicator();
        }

        if (msg.type === 'signify-notify') {
            showIndicator(msg.title, msg.body);
        }
    }

    function post(data) { window.postMessage(data, ORIGIN); }

    function send(msg, cb) {
        if (cb) { cid++; cbs[cid] = cb; msg._cid = cid; }
        safePost(msg);
    }

    function showIndicator(title, body) {
        if (indicator) return;
        var d = document.createElement('div');
        d.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;background:linear-gradient(135deg,#7c5cfc,#a78bfa);color:#fff;padding:14px 20px;border-radius:12px;font-family:-apple-system,sans-serif;box-shadow:0 8px 32px rgba(124,92,252,0.4);cursor:pointer;max-width:300px;animation:saIn .4s cubic-bezier(.22,1,.36,1);';
        d.innerHTML = '<div style="display:flex;align-items:center;gap:10px;"><div style="font-size:22px;">' + (title.indexOf('Key') > -1 ? '🔑' : '🔐') + '</div><div><div style="font-size:13px;font-weight:700;">' + title + '</div><div style="font-size:11px;opacity:.85;margin-top:2px;">' + body + '</div></div></div>';
        d.onclick = function () { d.remove(); indicator = null; };
        document.body.appendChild(d);
        indicator = d;
        if (!document.getElementById('sa-css')) {
            var s = document.createElement('style');
            s.id = 'sa-css';
            s.textContent = '@keyframes saIn{from{opacity:0;transform:translateX(30px)}to{opacity:1;transform:none}}';
            document.head.appendChild(s);
        }
        setTimeout(hideIndicator, 12000);
    }

    function hideIndicator() { if (indicator) { indicator.remove(); indicator = null; } }

    connect();

    window.addEventListener('message', function (e) {
        if (e.source !== window || !e.data || !e.data._signifyRequest) return;
        var r = e.data, rid = r._requestId;

        if (r.type === 'check-keys') {
            send({ type: 'signify-check-keys' }, function (d) {
                post({ _signifyResponse: true, _requestId: rid, available: !!(d && d.hasKeys),
                    hasKeys: d ? d.hasKeys : false, keyCount: d ? d.keyCount : 0,
                    activePublicKey: d ? d.activePublicKey : null });
            });
        }

        if (r.type === 'select-key') {
            send({ type: 'signify-select-key', _requestId: rid }, function (d) {
                post({ _signifyResponse: true, _requestId: rid, available: true,
                    selectedPublicKey: d ? d.selectedPublicKey : null });
            });
        }

        if (r.type === 'create-key' || r.type === 'sign') {
            send({
                type: r.type === 'create-key' ? 'signify-create-key' : 'signify-sign-request',
                _requestId: rid, requestId: rid,
                websiteName: r.data.websiteName, challenge: r.data.challenge,
                nonce: r.data.nonce, username: r.data.username,
                requestPublicKey: r.data.requestPublicKey,
                timestamp: Date.now()
            });
        }
    });
})();
