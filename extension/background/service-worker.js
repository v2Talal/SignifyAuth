// Service Worker v10.1 — Comprehensive error suppression

// Suppress ALL unhandled errors from chrome APIs
self.addEventListener('error', function (e) { e.preventDefault(); });
self.addEventListener('unhandledrejection', function (e) { e.preventDefault(); });

var pending = {};
var popupOpen = false;
var srcTab = null;
var contentPorts = {};
var popupPort = null;

chrome.runtime.onConnect.addListener(function (port) {
    try {
        // Content script connection
        if (port.name === 'signify') {
            var tabId = port.sender && port.sender.tab ? port.sender.tab.id : null;
            if (tabId) { contentPorts[tabId] = port; srcTab = tabId; }

            port.onMessage.addListener(function (msg) {
                try {
            if (msg.type === 'signify-check-keys') {
                chrome.storage.local.get(['signifyauth_keys_v2', 'signifyauth_active_key'], function (r) {
                    var keys = r.signifyauth_keys_v2 || [];
                    var aid = r.signifyauth_active_key || null;
                    var pk = null;
                    if (keys.length > 0) {
                        if (aid) { var f = keys.find(function (k) { return k.id === aid; }); if (f) pk = f.publicKey; }
                        if (!pk) pk = keys[0].publicKey;
                    }
                    try { port.postMessage({ _cid: msg._cid, data: { hasKeys: keys.length > 0, keyCount: keys.length, activePublicKey: pk } }); } catch (e) {}
                });
            }

            if (msg.type === 'signify-select-key') {
                pending['select-key-' + msg._cid] = msg;
                if (popupOpen && popupPort) {
                    try { popupPort.postMessage({ type: 'signify-select-key', _portCbId: msg._cid }); } catch (e) {}
                } else {
                    notify('🔐 Select Account', 'Click extension icon to choose account');
                }
            }

                    if (msg.type === 'signify-create-key') {
                        pending[msg._requestId] = msg;
                        notify('🔑 Create Key', 'Click extension icon to create');
                    }

                    if (msg.type === 'signify-sign-request') {
                        pending[msg.requestId] = msg;
                        if (popupOpen && popupPort) {
                            try { popupPort.postMessage(msg); } catch (e) {}
                        } else {
                            notify('🔐 Sign Request', 'Click extension icon to sign');
                        }
                    }
                } catch (e) {}
            });

            port.onDisconnect.addListener(function () {
                if (tabId) delete contentPorts[tabId];
                try { chrome.runtime.lastError; } catch (e) {}
            });
            return;
        }

        // Popup connection
        if (port.name === 'signify-popup') {
            popupPort = port;

            port.onMessage.addListener(function (msg) {
                try {
                    if (msg.type === 'signify-get-pending') {
                        try { port.postMessage({ _portCbId: msg._portCbId, data: { requests: pending } }); } catch (e) {}
                        pending = {};
                        return;
                    }
                    if (msg.type === 'signify-popup-opened') {
                        popupOpen = true;
                        try { chrome.action.setBadgeText({ text: '' }); } catch (e) {}
                        try { port.postMessage({ _portCbId: msg._portCbId, data: { ok: true } }); } catch (e) {}
                        return;
                    }
                    if (msg.type === 'signify-popup-closed') {
                        popupOpen = false;
                        try { port.postMessage({ _portCbId: msg._portCbId, data: { ok: true } }); } catch (e) {}
                        return;
                    }
        // Response from popup — route to content script
        if (msg.type === 'signify-sign-response' || msg.type === 'signify-create-response' || msg.type === 'signify-select-key-response') {
            routeToContent(msg);
            try { port.postMessage({ _portCbId: msg._portCbId, data: { ok: true } }); } catch (e) {}
            return;
        }
                } catch (e) {}
            });

            port.onDisconnect.addListener(function () {
                popupPort = null;
                popupOpen = false;
                try { chrome.runtime.lastError; } catch (e) {}
            });
        }
    } catch (e) {}
});

function routeToContent(msg) {
    if (srcTab && contentPorts[srcTab]) {
        try { contentPorts[srcTab].postMessage(msg); return; } catch (e) {}
    }
    if (srcTab) {
        try {
            chrome.tabs.sendMessage(srcTab, msg, function () {
                try { chrome.runtime.lastError; } catch (e) {}
            });
        } catch (e) {}
    }
    try {
        chrome.tabs.query({}, function (tabs) {
            for (var i = 0; i < tabs.length; i++) {
                try { chrome.tabs.sendMessage(tabs[i].id, msg); } catch (e) {}
            }
        });
    } catch (e) {}
}

function notify(title, body) {
    try {
        chrome.action.setBadgeText({ text: '!' });
        chrome.action.setBadgeBackgroundColor({ color: '#ff4d6a' });
        chrome.action.setTitle({ title: title + ' — ' + body });
    } catch (e) {}
    if (srcTab && contentPorts[srcTab]) {
        try { contentPorts[srcTab].postMessage({ type: 'signify-notify', title: title, body: body }); } catch (e) {}
    }
    if (srcTab) {
        try { chrome.tabs.sendMessage(srcTab, { type: 'signify-notify', title: title, body: body }); } catch (e) {}
    }
}

chrome.storage.onChanged.addListener(function (c, a) {
    if (a === 'local' && c.signifyauth_keys_v2) {
        var k = c.signifyauth_keys_v2.newValue || [];
        try {
            chrome.action.setBadgeText({ text: k.length > 0 ? k.length.toString() : '' });
            if (k.length > 0) chrome.action.setBadgeBackgroundColor({ color: '#7c5cfc' });
        } catch (e) {}
    }
});

// Fallback: handle any sendMessage calls that arrive before ports connect
chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
    try {
        if (msg.type === 'signify-check-keys') {
            chrome.storage.local.get(['signifyauth_keys_v2', 'signifyauth_active_key'], function (r) {
                try {
                    var keys = r.signifyauth_keys_v2 || [];
                    var aid = r.signifyauth_active_key || null;
                    var pk = null;
                    if (keys.length > 0) {
                        if (aid) { var f = keys.find(function (k) { return k.id === aid; }); if (f) pk = f.publicKey; }
                        if (!pk) pk = keys[0].publicKey;
                    }
                    respond({ hasKeys: keys.length > 0, keyCount: keys.length, activePublicKey: pk });
                } catch (e) { try { respond({ hasKeys: false }); } catch (e2) {} }
            });
            return true;
        }
        if (msg.type === 'signify-get-pending') { respond({ requests: pending }); pending = {}; return false; }
        if (msg.type === 'signify-popup-opened') { popupOpen = true; respond({ ok: true }); return false; }
        if (msg.type === 'signify-popup-closed') { popupOpen = false; respond({ ok: true }); return false; }
        if (msg.type === 'signify-sign-response' || msg.type === 'signify-create-response') { routeToContent(msg); respond({ ok: true }); return false; }
        respond({ ok: true });
    } catch (e) { try { respond({ ok: true }); } catch (e2) {} }
    return false;
});
