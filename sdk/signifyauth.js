/**
 * SignifyAuth SDK v2.1
 *
 * Drop-in passwordless authentication for any website.
 * Two-signature protocol: identity verification + session confirmation.
 *
 * Usage:
 *   <script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js"></script>
 *   <script src="https://your-domain.com/sdk/signifyauth.js"></script>
 *   <script>
 *     var auth = new SignifyAuth({ serverUrl: 'https://auth.example.com' });
 *
 *     // Register (generates key pair client-side)
 *     auth.register('alice').then(function (result) {
 *       console.log(result.userId, result.keyPair);
 *     });
 *
 *     // Login with private key (two signatures, fully automated)
 *     auth.login(secretKeyBase64).then(function (session) {
 *       console.log(session.sessionToken);
 *     });
 *
 *     // Login via extension (popup prompts for password)
 *     auth.loginWithExtension(publicKey).then(function (session) { ... });
 *   </script>
 */
(function (root) {
    'use strict';

    var NS = '__SignifyAuthSDK__';
    if (root[NS]) return;
    root[NS] = true;

    function SignifyAuth(config) {
        if (!config || !config.serverUrl) {
            throw new Error('SignifyAuth: serverUrl is required');
        }
        this.serverUrl = config.serverUrl.replace(/\/$/, '');
        this.siteName = (typeof document !== 'undefined' && document.title) || 'SignifyAuth';
        this._requestCounter = 0;
    }

    // ============================================================
    //  BASE64 UTILITIES (browser-safe)
    // ============================================================

    SignifyAuth._bufferToBase64 = function (buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    };

    SignifyAuth._base64ToBuffer = function (base64) {
        var binary = atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    };

    // ============================================================
    //  KEY GENERATION
    // ============================================================

    SignifyAuth.prototype.generateKeyPair = function () {
        if (typeof nacl === 'undefined') {
            throw new Error('SignifyAuth: tweetnacl not loaded. Include nacl-fast.min.js before signifyauth.js');
        }
        var keyPair = nacl.sign.keyPair();
        return {
            publicKey: SignifyAuth._bufferToBase64(keyPair.publicKey),
            secretKey: SignifyAuth._bufferToBase64(keyPair.secretKey)
        };
    };

    // ============================================================
    //  SIGNING
    // ============================================================

    SignifyAuth.prototype.sign = function (secretKeyBase64, message) {
        var secretKeyBytes = SignifyAuth._base64ToBuffer(secretKeyBase64);
        var messageBytes = new TextEncoder().encode(message);
        var signed = nacl.sign.detached(messageBytes, secretKeyBytes);
        secretKeyBytes.fill(0);
        return SignifyAuth._bufferToBase64(signed);
    };

    SignifyAuth.prototype.derivePublicKey = function (secretKeyBase64) {
        var keyBytes = SignifyAuth._base64ToBuffer(secretKeyBase64);
        var keyPair = nacl.sign.keyPair.fromSecretKey(keyBytes);
        var publicKey = SignifyAuth._bufferToBase64(keyPair.publicKey);
        keyBytes.fill(0);
        return publicKey;
    };

    // ============================================================
    //  HTTP HELPERS
    // ============================================================

    SignifyAuth.prototype._post = function (endpoint, body) {
        var self = this;
        return fetch(this.serverUrl + endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Site-Name': self.siteName
            },
            body: JSON.stringify(body)
        }).then(function (res) {
            return res.json().then(function (data) {
                if (!res.ok) {
                    throw new Error(data.error || 'Server error (' + res.status + ')');
                }
                return data;
            });
        }).catch(function (err) {
            if (err.message && err.message.indexOf('Server error') !== -1) throw err;
            throw new Error('Network error: ' + err.message);
        });
    };

    // ============================================================
    //  REGISTER
    // ============================================================

    SignifyAuth.prototype.register = function (username) {
        var keyPair = this.generateKeyPair();
        var self = this;

        return this._post('/api/register', {
            publicKey: keyPair.publicKey,
            username: username
        }).then(function (result) {
            return {
                userId: result.userId,
                username: username,
                keyPair: keyPair,
                publicKey: keyPair.publicKey
            };
        });
    };

    // ============================================================
    //  LOGIN — Two-Signature Protocol (direct, no extension)
    // ============================================================

    SignifyAuth.prototype.login = function (secretKeyBase64) {
        var self = this;
        var publicKey = this.derivePublicKey(secretKeyBase64);

        return this._post('/api/challenge', { publicKey: publicKey })
            .then(function (challengeResult) {
                var identitySignature = self.sign(secretKeyBase64, challengeResult.challenge);

                return self._post('/api/verify-identity', {
                    sessionId: challengeResult.sessionId,
                    signature: identitySignature,
                    publicKey: publicKey
                });
            })
            .then(function (identityResult) {
                var confirmationSignature = self.sign(secretKeyBase64, identityResult.confirmationChallenge);

                return self._post('/api/verify-confirmation', {
                    sessionId: identityResult.sessionId,
                    signature: confirmationSignature,
                    publicKey: publicKey
                });
            })
            .then(function (finalResult) {
                return {
                    sessionToken: finalResult.sessionToken,
                    userId: finalResult.userId,
                    username: finalResult.username
                };
            });
    };

    // ============================================================
    //  SESSION MANAGEMENT
    // ============================================================

    SignifyAuth.prototype.verifySession = function (sessionToken) {
        return this._post('/api/verify-session', { sessionToken: sessionToken });
    };

    SignifyAuth.prototype.logout = function (sessionToken) {
        return this._post('/api/logout', { sessionToken: sessionToken }).then(function () {
            return { success: true };
        });
    };

    // ============================================================
    //  EXTENSION COMMUNICATION
    // ============================================================

    SignifyAuth.prototype.requestSignatureFromExtension = function (options) {
        var self = this;
        return new Promise(function (resolve, reject) {
            if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
                return reject(new Error('SignifyAuth extension not installed'));
            }

            var requestId = 'req_' + (++self._requestCounter) + '_' + Date.now();
            var resolved = false;

            function handler(event) {
                if (event.source !== window) return;
                if (!event.data || event.data.type !== 'signify-sign-response') return;
                if (event.data.requestId !== requestId) return;
                if (resolved) return;
                resolved = true;
                window.removeEventListener('message', handler);
                clearTimeout(timer);

                if (event.data.approved) {
                    resolve({ signature: event.data.signature, publicKey: event.data.publicKey });
                } else {
                    reject(new Error('User rejected the sign request'));
                }
            }

            var timer = setTimeout(function () {
                if (resolved) return;
                resolved = true;
                window.removeEventListener('message', handler);
                reject(new Error('Sign request timed out'));
            }, options.timeout || 120000);

            window.addEventListener('message', handler);

            window.postMessage({
                type: 'signify-sign-request',
                requestId: requestId,
                websiteName: options.websiteName || self.siteName,
                challenge: options.challenge,
                nonce: options.nonce,
                timestamp: Date.now()
            }, window.location.origin);
        });
    };

    // ============================================================
    //  LOGIN WITH EXTENSION
    // ============================================================

    SignifyAuth.prototype.loginWithExtension = function (publicKey) {
        var self = this;
        var loginKey = publicKey;

        return this._post('/api/challenge', { publicKey: loginKey })
            .then(function (challengeResult) {
                return self.requestSignatureFromExtension({
                    websiteName: self.siteName,
                    challenge: challengeResult.challenge,
                    nonce: challengeResult.nonce,
                    requestPublicKey: loginKey
                }).then(function (sig1) {
                    return { challengeResult: challengeResult, sig1: sig1 };
                });
            })
            .then(function (data) {
                return self._post('/api/verify-identity', {
                    sessionId: data.challengeResult.sessionId,
                    signature: data.sig1.signature,
                    publicKey: loginKey
                }).then(function (identityResult) {
                    return { identityResult: identityResult };
                });
            })
            .then(function (data) {
                return self.requestSignatureFromExtension({
                    websiteName: self.siteName,
                    challenge: data.identityResult.confirmationChallenge,
                    nonce: 'confirm-' + Date.now(),
                    requestPublicKey: loginKey
                }).then(function (sig2) {
                    return self._post('/api/verify-confirmation', {
                        sessionId: data.identityResult.sessionId,
                        signature: sig2.signature,
                        publicKey: loginKey
                    });
                });
            })
            .then(function (finalResult) {
                return {
                    sessionToken: finalResult.sessionToken,
                    userId: finalResult.userId,
                    username: finalResult.username
                };
            });
    };

    // ============================================================
    //  EXPORT
    // ============================================================

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = SignifyAuth;
    } else {
        root.SignifyAuth = SignifyAuth;
    }
})(typeof window !== 'undefined' ? window : this);
