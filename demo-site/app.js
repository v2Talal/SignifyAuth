// SignifyAuth Demo Site v8.0 — Works with Chrome's popup limitations

var API_BASE = window.location.origin;
var userPublicKey = null;
var state = { currentView: 'hero', userId: null, sessionToken: null, username: null };

var $ = function (s) { return document.querySelector(s); };
var $$ = function (s) { return document.querySelectorAll(s); };

function askExt(type, data) {
    return new Promise(function (resolve) {
        var rid = 'ext_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);
        var done = false;
        function h(e) {
            if (e.source !== window) return;
            if (!e.data || !e.data._signifyResponse || e.data._requestId !== rid) return;
            if (done) return;
            done = true;
            window.removeEventListener('message', h);
            clearTimeout(t);
            resolve(e.data);
        }
        var t = setTimeout(function () {
            if (done) return;
            done = true;
            window.removeEventListener('message', h);
            resolve({ available: false, timedOut: true });
        }, 180000);
        window.addEventListener('message', h);
        window.postMessage({ _signifyRequest: true, _requestId: rid, type: type, data: data || {} }, window.location.origin);
    });
}

function checkExt() { return askExt('check-keys'); }
function createInExt(u) { return askExt('create-key', { username: u }); }
function signExt(ch, n, w, reqPubKey) {
    return askExt('sign', { challenge: ch, nonce: n, websiteName: w, requestPublicKey: reqPubKey });
}

function showToast(m, t) {
    var c = $('#toastContainer'), el = document.createElement('div');
    el.className = 'toast ' + (t || 'info'); el.textContent = m;
    c.appendChild(el); setTimeout(function () { el.remove(); }, 3500);
}

function showView(v) {
    $$('.panel, .hero').forEach(function (e) { e.classList.add('hidden'); });
    state.currentView = v;
    var map = { hero: 'heroSection', register: 'registerPanel', login: 'loginPanel', dashboard: 'dashboardPanel' };
    if (map[v]) $('#' + map[v]).classList.remove('hidden');
    updateHeaderStatus(v === 'dashboard' ? 'Logged in as ' + state.username : '');
}

function updateHeaderStatus(t) { $('#headerStatus').textContent = t; }
function setStatus(el, m, t) { el.textContent = m; el.className = 'status-box visible ' + (t || 'info'); }

function apiPost(ep, body) {
    return fetch(API_BASE + ep, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        .then(function (r) { return r.json().then(function (d) { if (!r.ok) throw new Error(d.error || 'Server error'); return d; }); });
}

// ── CREATE IDENTITY ──
$('#btnCreateID').addEventListener('click', function () {
    var username = prompt('Enter a display name:');
    if (!username || !username.trim()) return;
    showView('register');
    setStatus($('#regStatus'), '⏳ Click the SignifyAuth extension icon in your toolbar, then create a key.', 'info');

    createInExt(username.trim()).then(function (resp) {
        if (resp.available && resp.publicKey) {
            userPublicKey = resp.publicKey;
            setStatus($('#regStatus'), 'Key created! Registering...', 'info');
            apiPost('/api/register', { publicKey: resp.publicKey, username: username.trim() })
                .then(function (r) {
                    state.userId = r.userId; state.username = username.trim();
                    setStatus($('#regStatus'), '✅ Registered! ID: ' + r.userId, 'success');
                    showToast('Identity created!', 'success');
                    setTimeout(function () {
                        showView('dashboard');
                        $('#dashboardUsername').textContent = username.trim();
                        $('#dashboardUserId').textContent = 'ID: ' + r.userId;
                        $('#userAvatar').textContent = username.trim().charAt(0).toUpperCase();
                    }, 1200);
                }).catch(function (e) {
                    state.username = username.trim();
                    setStatus($('#regStatus'), '✅ Saved locally. ' + e.message, 'success');
                    setTimeout(function () {
                        showView('dashboard');
                        $('#dashboardUsername').textContent = username.trim();
                        $('#userAvatar').textContent = username.trim().charAt(0).toUpperCase();
                    }, 1200);
                });
        } else if (resp.timedOut) {
            setStatus($('#regStatus'), '⏳ Still waiting... Click the extension icon in your toolbar.', 'info');
        } else {
            setStatus($('#regStatus'), 'Extension closed. Click the extension icon and create a key.', 'error');
        }
    });
});

$('#btnBackReg').addEventListener('click', function () { showView('hero'); });

// ── LOGIN ──
$('#btnLogin').addEventListener('click', function () {
    showView('login');
    setStatus($('#loginStatus'), '⏳ Opening extension — select an account...', 'info');

    checkExt().then(function (resp) {
        if (!resp.available) { setStatus($('#loginStatus'), '❌ Extension not found', 'error'); return; }
        if (!resp.hasKeys) { setStatus($('#loginStatus'), '⚠️ No keys', 'error'); return; }

        // Ask extension which key to use
        setStatus($('#loginStatus'), '⏳ Select account in the extension popup...', 'info');
        return askExt('select-key').then(function (sel) {
            if (!sel || !sel.available || !sel.selectedPublicKey) {
                throw new Error('No account selected');
            }
            userPublicKey = sel.selectedPublicKey;
            doLogin();
        });
    }).catch(function (e) {
        setStatus($('#loginStatus'), '❌ ' + e.message, 'error');
    });
});

$('#btnBackLogin').addEventListener('click', function () { showView('hero'); });

function doLogin() {
    var st = $('#loginStatus');
    for (var i = 1; i <= 5; i++) { var s = $('#loginStep' + i); if (s) { s.className = 'login-step'; s.querySelector('.login-step-icon').textContent = '⏳'; } }

    setStatus(st, '⏳ Requesting challenge...', 'info');
    $('#loginStep1').classList.add('active');

    // ALWAYS use userPublicKey for all server calls
    var loginKey = userPublicKey;

    apiPost('/api/challenge', { publicKey: loginKey })
        .then(function (ch) {
            $('#loginStep1').classList.remove('active');
            $('#loginStep1').classList.add('done');
            $('#loginStep1').querySelector('.login-step-icon').textContent = '✓';

            $('#loginStep2').classList.add('active');
            setStatus(st, '⏳ Click extension icon → enter password → sign', 'info');

            return signExt(ch.challenge, ch.nonce, document.title, loginKey).then(function (sig) {
                if (!sig.available || !sig.approved) throw new Error(sig.error || 'Signing failed');
                $('#loginStep2').classList.remove('active');
                $('#loginStep2').classList.add('done');
                $('#loginStep2').querySelector('.login-step-icon').textContent = '✓';
                return { identitySignature: sig.identitySignature, sessionId: ch.sessionId };
            });
        })
        .then(function (data) {
            $('#loginStep3').classList.add('active');
            // Use loginKey, NOT sig.publicKey
            return apiPost('/api/verify-identity', { sessionId: data.sessionId, signature: data.identitySignature, publicKey: loginKey })
                .then(function (r) {
                    $('#loginStep3').classList.remove('active');
                    $('#loginStep3').classList.add('done');
                    $('#loginStep3').querySelector('.login-step-icon').textContent = '✓';
                    return { sessionId: data.sessionId, confirmationChallenge: r.confirmationChallenge };
                });
        })
        .then(function (data) {
            $('#loginStep4').classList.add('active');
            setStatus(st, '⏳ Extension signing confirmation...', 'info');

            return signExt(data.confirmationChallenge, 'conf-' + Date.now(), document.title, loginKey).then(function (sig) {
                if (!sig.available || !sig.approved) throw new Error(sig.error || 'Confirmation failed');
                $('#loginStep4').classList.remove('active');
                $('#loginStep4').classList.add('done');
                $('#loginStep4').querySelector('.login-step-icon').textContent = '✓';
                return { confirmationSignature: sig.confirmationSignature, sessionId: data.sessionId };
            });
        })
        .then(function (data) {
            $('#loginStep5').classList.add('active');
            // Use loginKey for confirmation too
            return apiPost('/api/verify-confirmation', { sessionId: data.sessionId, signature: data.confirmationSignature, publicKey: loginKey })
                .then(function (r) { $('#loginStep5').classList.remove('active'); $('#loginStep5').classList.add('done'); $('#loginStep5').querySelector('.login-step-icon').textContent = '✓'; return r; });
        })
        .then(function (r) {
            state.sessionToken = r.sessionToken; state.userId = r.userId; state.username = r.username;
            setStatus(st, '✅ Logged in!', 'success');
            showToast('Welcome, ' + r.username + '!', 'success');
            $('#dashboardUsername').textContent = r.username;
            $('#dashboardUserId').textContent = 'ID: ' + r.userId;
            $('#userAvatar').textContent = r.username.charAt(0).toUpperCase();
            setTimeout(function () { showView('dashboard'); }, 800);
        })
        .catch(function (e) { setStatus(st, '❌ ' + e.message, 'error'); });
}

// ── DASHBOARD ──
$('#btnLogout').addEventListener('click', function () {
    if (state.sessionToken) apiPost('/api/logout', { sessionToken: state.sessionToken });
    state.sessionToken = null; state.userId = null; state.username = null;
    localStorage.removeItem('signifyauth_session');
    showView('hero'); showToast('Logged out', 'info');
});

// ── SESSION ──
function checkSession() {
    var s = localStorage.getItem('signifyauth_session');
    if (!s) return;
    try {
        var d = JSON.parse(s);
        apiPost('/api/verify-session', { sessionToken: d.sessionToken }).then(function (r) {
            if (r.valid) {
                state.sessionToken = d.sessionToken; state.userId = r.userId; state.username = r.username;
                $('#dashboardUsername').textContent = r.username;
                $('#dashboardUserId').textContent = 'ID: ' + r.userId;
                $('#userAvatar').textContent = r.username.charAt(0).toUpperCase();
                showView('dashboard');
            } else { localStorage.removeItem('signifyauth_session'); }
        }).catch(function () { localStorage.removeItem('signifyauth_session'); });
    } catch (e) { localStorage.removeItem('signifyauth_session'); }
}
var origShowView = showView;
showView = function (v) {
    origShowView(v);
    if (v === 'dashboard' && state.sessionToken) localStorage.setItem('signifyauth_session', JSON.stringify({ sessionToken: state.sessionToken }));
    else if (v === 'hero') localStorage.removeItem('signifyauth_session');
};
checkSession();
