/**
 * fido2.js — Client-side FIDO2 / WebAuthn helper library
 *
 * Exposes a single `Fido2` namespace with two async functions:
 *   - Fido2.register(username, displayName) → { credentialId }
 *   - Fido2.authenticate(username)          → { username }
 *
 * All ArrayBuffer <-> base64url conversions are handled internally so callers
 * only work with plain JS objects and strings.
 */
(function (global) {
  'use strict';

  const BASE_URL = '/api/v1';

  // ── Public API ────────────────────────────────────────────────────────────

  const Fido2 = {

    /**
     * Runs a full FIDO2 registration ceremony:
     *   1. POST /api/v1/registration/initiate  →  PublicKeyCredentialCreationOptions
     *   2. navigator.credentials.create()
     *   3. POST /api/v1/registration/complete
     *
     * @param {string} username    Account identifier (e.g. email address)
     * @param {string} displayName Human-readable name for authenticator prompts
     * @returns {Promise<{credentialId: string}>}
     */
    async register(username, displayName) {
      logInfo(`[Fido2] Starting registration for "${username}"`);

      // ── Step 1: Get creation options from server ────────────────────────
      const initResp = await apiPost('/registration/initiate', {
        username,
        displayName: displayName || username,
      });
      logInfo('[Fido2] Registration options received', initResp);

      // ── Step 2: Build PublicKeyCredentialCreationOptions ───────────────
      const creationOptions = {
        challenge:         base64urlToBuffer(initResp.challenge),
        rp: {
          id:   initResp.rp.id,
          name: initResp.rp.name,
        },
        user: {
          id:          base64urlToBuffer(initResp.user.id),
          name:        initResp.user.name,
          displayName: initResp.user.displayName,
        },
        pubKeyCredParams: initResp.pubKeyCredParams,
        excludeCredentials: (initResp.excludeCredentials || []).map(c => ({
          type:       c.type,
          id:         base64urlToBuffer(c.id),
          transports: c.transports || [],
        })),
        timeout:     initResp.timeout || 60000,
        attestation: initResp.attestation || 'none',
      };

      // ── Step 3: Invoke browser WebAuthn API ────────────────────────────
      logInfo('[Fido2] Calling navigator.credentials.create()…');
      let credential;
      try {
        credential = await navigator.credentials.create({ publicKey: creationOptions });
      } catch (err) {
        throw new Error(`WebAuthn create() failed: ${err.message || err}`);
      }
      logInfo('[Fido2] Credential created', { id: credential.id, type: credential.type });

      // ── Step 4: Collect transports (optional but recommended) ──────────
      let transports = [];
      if (credential.response.getTransports) {
        try {
          transports = credential.response.getTransports();
        } catch (_) { /* older browsers may not support this */ }
      }

      // ── Step 5: Submit attestation to server ───────────────────────────
      const completePayload = {
        sessionId:        initResp.sessionId,
        credentialId:     bufferToBase64url(credential.rawId),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        clientDataJSON:   bufferToBase64url(credential.response.clientDataJSON),
        transports,
      };

      logInfo('[Fido2] Submitting registration completion…', { sessionId: initResp.sessionId });
      const completeResp = await apiPost('/registration/complete', completePayload);
      logInfo('[Fido2] Registration complete', completeResp);

      return completeResp;
    },

    /**
     * Runs a full FIDO2 authentication ceremony:
     *   1. POST /api/v1/authentication/initiate  →  PublicKeyCredentialRequestOptions
     *   2. navigator.credentials.get()
     *   3. POST /api/v1/authentication/complete
     *
     * @param {string} username Account identifier of the user signing in
     * @returns {Promise<{success: boolean, username: string}>}
     */
    async authenticate(username) {
      logInfo(`[Fido2] Starting authentication for "${username}"`);

      // ── Step 1: Get request options from server ────────────────────────
      const initResp = await apiPost('/authentication/initiate', { username });
      logInfo('[Fido2] Authentication options received', initResp);

      // ── Step 2: Build PublicKeyCredentialRequestOptions ─────────────
      const requestOptions = {
        challenge:        base64urlToBuffer(initResp.challenge),
        rpId:             initResp.rpId,
        allowCredentials: (initResp.allowCredentials || []).map(c => ({
          type:       c.type,
          id:         base64urlToBuffer(c.id),
          transports: c.transports || [],
        })),
        timeout:          initResp.timeout || 60000,
        userVerification: initResp.userVerification || 'preferred',
      };

      // ── Step 3: Invoke browser WebAuthn API ────────────────────────────
      logInfo('[Fido2] Calling navigator.credentials.get()…');
      let assertion;
      try {
        assertion = await navigator.credentials.get({ publicKey: requestOptions });
      } catch (err) {
        throw new Error(`WebAuthn get() failed: ${err.message || err}`);
      }
      logInfo('[Fido2] Assertion received', { id: assertion.id, type: assertion.type });

      // ── Step 4: Submit assertion to server ─────────────────────────────
      const completePayload = {
        sessionId:       initResp.sessionId,
        credentialId:    bufferToBase64url(assertion.rawId),
        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
        clientDataJSON:  bufferToBase64url(assertion.response.clientDataJSON),
        signature:       bufferToBase64url(assertion.response.signature),
        userHandle:      assertion.response.userHandle
                           ? bufferToBase64url(assertion.response.userHandle)
                           : null,
      };

      logInfo('[Fido2] Submitting authentication completion…', { sessionId: initResp.sessionId });
      const completeResp = await apiPost('/authentication/complete', completePayload);
      logInfo('[Fido2] Authentication complete', completeResp);

      return completeResp;
    },
  };

  // ── Internal helpers ──────────────────────────────────────────────────────

  /**
   * HTTP POST helper.
   * Throws a descriptive Error when the server returns a non-2xx status.
   */
  async function apiPost(path, body) {
    const url = `${BASE_URL}${path}`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Correlation-Id': generateCorrelationId(),
      },
      body: JSON.stringify(body),
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      // Surface the RFC 9457 ProblemDetail detail field if present
      const detail = data.detail || data.message || `HTTP ${resp.status}`;
      throw new Error(`Server error (${resp.status}): ${detail}`);
    }

    return data;
  }

  /**
   * Converts a base64url string (no padding) to an ArrayBuffer.
   * Handles padding, and the + → - / / → _ substitutions.
   */
  function base64urlToBuffer(base64url) {
    // Normalise base64url → base64
    const base64 = base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    // Add padding
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');

    const binary = atob(padded);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Converts an ArrayBuffer (or ArrayBufferView) to a base64url string (no padding).
   */
  function bufferToBase64url(bufferOrView) {
    const bytes = bufferOrView instanceof ArrayBuffer
      ? new Uint8Array(bufferOrView)
      : new Uint8Array(bufferOrView.buffer, bufferOrView.byteOffset, bufferOrView.byteLength);

    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g,  '');
  }

  /** Generates a random UUID-like correlation ID for request tracing. */
  function generateCorrelationId() {
    if (crypto && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  function logInfo(message, data) {
    if (data !== undefined) {
      console.debug(message, data);
    } else {
      console.debug(message);
    }
  }

  // ── Export ────────────────────────────────────────────────────────────────
  global.Fido2 = Fido2;

})(window);
