/**
 * @file errorHandler.js
 * @description Security middleware for IIITA-Crypt.
 * Provides two utilities:
 *   1. sanitizeLogMessage — strips crypto material before logging (Rule 3.2)
 *   2. redactChunkOnError — graceful chunk redaction on decryption failure (Rule 3)
 */

/**
 * Case 3.2 — Sanitizes an error message before writing to logs.
 * Strips raw base64 blobs, long hex strings, Python tracebacks, and
 * ciphertext fragments that must never appear in plaintext log output.
 *
 * @param {string} msg Raw error message string.
 * @returns {string} Sanitized, log-safe string.
 */
export const sanitizeLogMessage = (msg) => {
    if (typeof msg !== 'string') msg = String(msg);
    return msg
        // Remove base64 payloads (40+ chars of b64 alphabet)
        .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[BASE64_REDACTED]')
        // Remove long hex strings (sha256 / hmac digests)
        .replace(/[0-9a-fA-F]{32,}/g, '[HEX_REDACTED]')
        // Remove Python tracebacks
        .replace(/Traceback \(most recent call last\)[\s\S]*?(?=\n[A-Z]|$)/g, '[TRACEBACK_REDACTED]')
        // Truncate anything still very long
        .substring(0, 300);
};

/**
 * Rule 3 — Gracefully redacts a document chunk if the Python decryption
 * service fails. Prevents the entire LLM prompt from crashing due to a
 * single unauthorized or corrupted chunk.
 *
 * @param {Object} chunk The original chunk object from MongoDB / pipeline.
 * @param {Error} error The error thrown during decryption attempt.
 * @returns {Object} Redacted chunk representation with title preserved.
 */
export const redactChunkOnError = (chunk, error) => {
    const label = chunk.title || chunk.chunk_id || 'unknown';
    const safeMsg = sanitizeLogMessage(error.message || String(error));
    console.error(`[Rule 3] Decryption failed for "${label}": ${safeMsg}`);

    return {
        title: chunk.title || 'Restricted Document',
        policy: chunk.metadata?.policy || chunk.policy || 'Classified',
        plaintext: `[REDACTED: Access Denied — Administrative clearance required]`,
        status: 'redacted'
    };
};
