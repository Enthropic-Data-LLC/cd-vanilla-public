// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.UUID;

/**
 * One P-256 keypair, or a public key alone when {@link #privateKey()} is null.
 *
 * <p>The same key material serves both ECDH (wrapping) and ECDSA (header
 * signatures): §4.1 re-imports the identical P-256 scalar under a different
 * algorithm label. The JDK models an EC key by its curve rather than its use, so
 * one object does both jobs.
 */
public final class KeyRecord {

    private final String label;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String keyId;
    private final long createdAt;

    public KeyRecord(String label, PrivateKey privateKey, PublicKey publicKey,
            String keyId, long createdAt) {
        this.label = label == null || label.isEmpty() ? "(unnamed)" : label;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.keyId = keyId == null || keyId.isEmpty() ? UUID.randomUUID().toString() : keyId;
        this.createdAt = createdAt == 0 ? now() : createdAt;
    }

    /** Create a fresh P-256 keypair. */
    public static KeyRecord generate(String label) {
        KeyPair pair = CellCrypto.generateKeyPair();
        return new KeyRecord(label, pair.getPrivate(), pair.getPublic(), null, 0);
    }

    public String label() {
        return label;
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    public String keyId() {
        return keyId;
    }

    public long createdAt() {
        return createdAt;
    }

    /** DER SubjectPublicKeyInfo bytes. */
    public byte[] spkiBytes() {
        return publicKey.getEncoded();
    }

    /** Base64 SPKI as it appears in a cell. */
    public String spki() {
        return CellCrypto.encodeB64(spkiBytes());
    }

    /** {@code SHA-256(SPKI)[..8]} in hex — spec §13.3. */
    public String fingerprint() {
        return CellCrypto.fingerprint(spkiBytes());
    }

    /** Render the {@code .cdpub} public key export — spec §13.1. */
    public Map<String, Object> toCdpub() {
        return Json.of(
                "cd_pubkey", "2.0",
                "label", label,
                "fingerprint", fingerprint(),
                "method", "ecdh-p256",
                "spki", spki());
    }

    /** Render the {@code .cdkey} full key export — spec §13.2. */
    public Map<String, Object> toCdkey() {
        if (privateKey == null) {
            throw new CellException.Malformed("cannot export a .cdkey from a public-only record");
        }
        return Json.of(
                "cd_key", "2.0",
                "keyId", keyId,
                "label", label,
                "method", "ecdh-p256",
                "fingerprint", fingerprint(),
                "spki", spki(),
                "pkcs8", CellCrypto.encodeB64(privateKey.getEncoded()),
                "created_at", (double) createdAt,
                "exported_at", (double) now());
    }

    /** Load a {@code .cdpub} document. */
    public static KeyRecord fromCdpub(Map<String, Object> doc) {
        String spki = Json.string(doc, "spki");
        if (spki == null) {
            throw new CellException.Malformed(".cdpub is missing its spki field");
        }
        PublicKey publicKey = CellCrypto.parseSpki(CellCrypto.decodeB64(spki, "spki"));
        KeyRecord record = new KeyRecord(Json.string(doc, "label"), null, publicKey, null, 0);

        // The fingerprint is derived, not authoritative. A mismatch means the
        // file was edited or corrupted, and trusting the claim would let an
        // attacker point a known-good label at a key they control.
        String claimed = Json.string(doc, "fingerprint");
        if (claimed != null && !claimed.equals(record.fingerprint())) {
            throw new CellException.Malformed(".cdpub fingerprint \"" + claimed
                    + "\" does not match its own SPKI (" + record.fingerprint() + ")");
        }
        return record;
    }

    /** Load a {@code .cdkey} document. */
    public static KeyRecord fromCdkey(Map<String, Object> doc) {
        String pkcs8 = Json.string(doc, "pkcs8");
        if (pkcs8 == null) {
            throw new CellException.Malformed(".cdkey is missing its pkcs8 field");
        }
        PrivateKey privateKey = CellCrypto.parsePkcs8(CellCrypto.decodeB64(pkcs8, "pkcs8"));
        String spki = Json.string(doc, "spki");
        if (spki == null) {
            throw new CellException.Malformed(".cdkey is missing its spki field");
        }
        PublicKey publicKey = CellCrypto.parseSpki(CellCrypto.decodeB64(spki, "spki"));
        return new KeyRecord(Json.string(doc, "label"), privateKey, publicKey,
                safeKeyId(Json.string(doc, "keyId")), Json.integer(doc, "created_at", 0));
    }

    /**
     * Constrain an imported {@code keyId} to a safe charset, else mint a fresh
     * one. Imported key files are attacker-supplied: the reference sanitises
     * this because it reaches the DOM there, and it reaches filenames and logs
     * here.
     */
    private static String safeKeyId(String id) {
        if (id == null || id.isEmpty() || id.length() > 64) {
            return UUID.randomUUID().toString();
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) {
                return UUID.randomUUID().toString();
            }
        }
        return id;
    }

    /** Seconds since the Unix epoch. */
    public static long now() {
        return System.currentTimeMillis() / 1000L;
    }
}
