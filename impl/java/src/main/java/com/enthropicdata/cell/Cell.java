// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Sealing and opening {@code .cell} documents — spec §4, §5, §10, §12. */
public final class Cell {

    private Cell() {}

    /** The version this library writes. */
    public static final String CELL_FORMAT_VERSION = "1.3";

    /** Versions this library can read (spec §12). */
    public static final Set<String> SUPPORTED_VERSIONS = Set.of("1.0", "1.1", "1.2", "1.3");

    /**
     * Versions whose hash/signature/AAD use the canonical serialization (§4.1.1).
     *
     * <p>Held as a set on purpose. §12 warns that adding a version to
     * {@link #SUPPORTED_VERSIONS} while leaving an inline {@code version.equals("1.2")}
     * test elsewhere silently drops canonicalization, or decrypts new cells with
     * no AAD, with no error raised at any point.
     */
    public static final Set<String> CANONICAL_VERSIONS = Set.of("1.2", "1.3");

    /** Versions that bind metadata to the ciphertext as AES-GCM AAD (§4.4). */
    public static final Set<String> AAD_VERSIONS = Set.of("1.1", "1.2", "1.3");

    // ─── Serialization ──────────────────────────────────────────────────────

    /**
     * Bytes that {@code header_hash} and {@code header_sig} cover (§4.1.1).
     *
     * <p>v1.2/v1.3 canonicalize; v1.0/v1.1 keep the original insertion-ordered
     * {@code JSON.stringify} form, which means those versions can only be
     * verified from a header still in its on-disk key order.
     */
    public static byte[] serializeHeader(Map<String, Object> header, String version) {
        if (CANONICAL_VERSIONS.contains(version)) {
            return Canonical.canonicalBytes(header);
        }
        return Canonical.jsStringify(header).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Additional authenticated data for the payload (§4.4).
     *
     * <p>The four fields fixed <em>before</em> encryption, in a fixed order, as
     * an array. {@code access_map} and {@code payload_hash} are absent because
     * they do not exist yet at encryption time — {@code header_hash} and
     * {@code header_sig} cover those instead. Returns null for versions that
     * bind no AAD.
     */
    public static byte[] cellAad(Map<String, Object> header, String version) {
        if (!AAD_VERSIONS.contains(version)) {
            return null;
        }
        List<Object> meta = new ArrayList<>(4);
        meta.add(header.get("prev_hash"));
        meta.add(header.get("threshold"));
        meta.add(header.get("lifetime"));
        meta.add(header.get("policy"));
        if ("1.1".equals(version)) {
            return Canonical.jsStringify(meta).getBytes(StandardCharsets.UTF_8);
        }
        return Canonical.canonicalBytes(meta);
    }

    // ─── Recipients ─────────────────────────────────────────────────────────

    /** One access-map entry to be created. */
    public record Recipient(String method, String label, String spki, String passphrase) {

        /** Wrap for the holder of a P-256 public key (base64 SPKI). */
        public static Recipient ecdh(String spki, String label) {
            return new Recipient("ecdh-p256", label, spki, null);
        }

        /** Wrap for the holder of a {@link KeyRecord}. */
        public static Recipient forKey(KeyRecord key) {
            return new Recipient("ecdh-p256", key.label(), key.spki(), null);
        }

        /** Wrap under a passphrase. */
        public static Recipient passphrase(String passphrase, String label) {
            return new Recipient("pbkdf2", label == null || label.isEmpty() ? "Passphrase" : label,
                    null, passphrase);
        }
    }

    private static Map<String, Object> wrapEntry(Recipient recipient, byte[] keyMaterial,
            Integer shareIndex) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("label", recipient.label());
        entry.put("method", recipient.method());

        Map<String, Object> wrapped;
        switch (recipient.method()) {
            case "ecdh-p256" -> {
                byte[] recipientDer = CellCrypto.decodeB64(recipient.spki(), "spki");
                entry.put("fingerprint", CellCrypto.fingerprint(recipientDer));
                PublicKey recipientKey = CellCrypto.parseSpki(recipientDer);

                // A fresh ephemeral keypair per recipient per cell is what gives
                // the format its per-cell forward secrecy.
                var ephemeral = CellCrypto.generateKeyPair();
                byte[] shared = CellCrypto.ecdhSharedSecret(ephemeral.getPrivate(), recipientKey);
                byte[] salt = CellCrypto.randomBytes(32);
                byte[] wrappingKey = CellCrypto.hkdf(shared, salt, CellCrypto.HKDF_INFO, 32);
                wrapped = Json.of(
                        "eph_spki", CellCrypto.encodeB64(ephemeral.getPublic().getEncoded()),
                        "hkdf_salt", CellCrypto.encodeB64(salt),
                        "ct", CellCrypto.encodeB64(CellCrypto.aesKeyWrap(wrappingKey, keyMaterial)));
                CellCrypto.wipe(wrappingKey);
            }
            case "pbkdf2" -> {
                byte[] salt = CellCrypto.randomBytes(32);
                byte[] wrappingKey = CellCrypto.derivePassphraseKey(
                        recipient.passphrase(), salt, CellCrypto.PBKDF2_ITERATIONS);
                wrapped = Json.of(
                        "salt", CellCrypto.encodeB64(salt),
                        "iterations", (double) CellCrypto.PBKDF2_ITERATIONS,
                        "ct", CellCrypto.encodeB64(CellCrypto.aesKeyWrap(wrappingKey, keyMaterial)));
                CellCrypto.wipe(wrappingKey);
                // A passphrase has no public key, so §6.2 fingerprints the salt.
                // It identifies the entry, not the holder, and proves nothing
                // about who can open it.
                entry.put("fingerprint", CellCrypto.fingerprint(salt));
            }
            default -> throw new CellException.Malformed(
                    "unknown access method \"" + recipient.method() + "\"");
        }

        // §6.4: on non-quorum cells the key is OMITTED, not written as null. The
        // choice is not cosmetic — canonicalization preserves an explicit null,
        // so the two forms hash differently. Both verify; they are not
        // byte-identical.
        if (shareIndex != null) {
            entry.put("share_index", (double) shareIndex);
        }
        entry.put("wrapped_cek", wrapped);
        return entry;
    }

    // ─── Sealing ────────────────────────────────────────────────────────────

    /** Options for {@link #create}. All fields are optional. */
    public static final class CreateOptions {
        public String contentType;
        public int threshold = 1;
        public Map<String, Object> lifetime;
        public Map<String, Object> policy;
        public String prevHash;
        public Object meta;
        public KeyRecord sender;
        public String docId;
        public Long createdAt;
    }

    /**
     * Seal {@code data} into a v1.3 cell.
     *
     * <p>A threshold above 1 splits the CEK into one Shamir share per recipient,
     * of which that many are needed (§7). {@code sender} adds a
     * {@code header_sig}; note that its <em>absence</em> is undetectable to a
     * reader (§4.1), so a signature proves authorship while no signature proves
     * nothing at all.
     */
    public static Map<String, Object> create(byte[] data, String filename,
            List<Recipient> recipients, CreateOptions options) {
        if (recipients == null || recipients.isEmpty()) {
            throw new CellException.Malformed("a cell needs at least one recipient");
        }
        CreateOptions opts = options == null ? new CreateOptions() : options;
        int required = Math.max(1, Math.min(opts.threshold, recipients.size()));
        String contentType = opts.contentType == null || opts.contentType.isEmpty()
                ? "application/octet-stream" : opts.contentType;

        // Manifest-prefixed plaintext (§5): filename, type and size live inside
        // the ciphertext, so an observer of the stored cell learns none of them.
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("filename", filename);
        manifest.put("content_type", contentType);
        manifest.put("size", (double) data.length);
        if (opts.meta != null) {
            manifest.put("meta", opts.meta);
        }
        byte[] manifestBytes = Canonical.jsStringify(manifest).getBytes(StandardCharsets.UTF_8);

        byte[] plaintext = new byte[4 + manifestBytes.length + data.length];
        ByteBuffer.wrap(plaintext).order(ByteOrder.LITTLE_ENDIAN).putInt(manifestBytes.length);
        System.arraycopy(manifestBytes, 0, plaintext, 4, manifestBytes.length);
        System.arraycopy(data, 0, plaintext, 4 + manifestBytes.length, data.length);
        byte[] body = CellCrypto.gzipCompress(plaintext);

        byte[] cek = CellCrypto.randomBytes(CellCrypto.CEK_LENGTH);
        try {
            // Metadata is fixed before encryption precisely so it can be bound as AAD.
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("prev_hash", opts.prevHash);
            header.put("threshold",
                    Json.of("required", (double) required, "of_total", (double) recipients.size()));
            Map<String, Object> lifetime = Lifetime.normalize(opts.lifetime);
            header.put("lifetime", lifetime == null ? Lifetime.permanent() : lifetime);
            header.put("policy", opts.policy != null ? opts.policy : Json.of(
                    "copy_protection", "standard",
                    "watermark_mode", "none",
                    "created_on_origin", null,
                    "origin_sig", null));

            byte[] iv = CellCrypto.randomBytes(CellCrypto.IV_LENGTH);
            byte[] ciphertext = CellCrypto.aesGcmEncrypt(cek, iv, body,
                    cellAad(header, CELL_FORMAT_VERSION));

            List<Object> accessMap = new ArrayList<>(recipients.size());
            if (required > 1) {
                List<Gf256.Share> shares = Gf256.split(cek, recipients.size(), required, null);
                for (int i = 0; i < recipients.size(); i++) {
                    accessMap.add(wrapEntry(recipients.get(i), shares.get(i).data(), i + 1));
                }
            } else {
                for (Recipient recipient : recipients) {
                    accessMap.add(wrapEntry(recipient, cek, null));
                }
            }
            header.put("access_map", accessMap);
            header.put("payload_hash", CellCrypto.encodeB64(CellCrypto.sha256(ciphertext)));

            byte[] headerBytes = serializeHeader(header, CELL_FORMAT_VERSION);

            Map<String, Object> cell = new LinkedHashMap<>();
            cell.put("version", CELL_FORMAT_VERSION);
            cell.put("doc_id", opts.docId != null ? opts.docId : Ulid.generate());
            cell.put("created_at",
                    (double) (opts.createdAt != null ? opts.createdAt : KeyRecord.now()));
            cell.put("header", header);
            cell.put("header_hash", CellCrypto.encodeB64(CellCrypto.sha256(headerBytes)));

            if (opts.sender != null) {
                PrivateKey signingKey = opts.sender.privateKey();
                if (signingKey == null) {
                    throw new CellException.Malformed(
                            "signing requires a key record with a private key");
                }
                cell.put("header_sig",
                        CellCrypto.encodeB64(CellCrypto.ecdsaSign(signingKey, headerBytes)));
                cell.put("header_sig_by", opts.sender.fingerprint());
                cell.put("header_sig_key", opts.sender.spki());
            } else {
                cell.put("header_sig", null);
                cell.put("header_sig_by", null);
                cell.put("header_sig_key", null);
            }

            cell.put("payload", Json.of(
                    "alg", "AES-256-GCM",
                    "encoding", "base64+gzip",
                    "iv", CellCrypto.encodeB64(iv),
                    "ciphertext", CellCrypto.encodeB64(ciphertext)));
            return cell;
        } finally {
            CellCrypto.wipe(cek);
        }
    }

    // ─── Key-free verification — spec §10 steps 1-3 ─────────────────────────

    /** Outcome of the checks that need no key material at all. */
    public record VerifyResult(
            String version,
            boolean payloadHashOk,
            boolean signed,
            /* Real fingerprint of header_sig_key — the only trustworthy identity here. */
            String signerFingerprint,
            /* header_sig_by: self-asserted, never to be trusted on its own (§4.1). */
            String claimedSigner) {}

    /**
     * Verify a cell's audit chain without opening it (§10).
     *
     * <p>That this is possible with no key is the property being demonstrated:
     * any third party can confirm a cell has not been altered since it was
     * sealed.
     *
     * <p>A clean return does <b>not</b> establish authorship. An attacker can
     * strip {@code header_sig} entirely and the result is indistinguishable from
     * a cell that was never signed, so pass {@code expectedSigner} (a
     * fingerprint learned out of band) whenever authorship matters.
     */
    public static VerifyResult verify(Map<String, Object> cell, String expectedSigner) {
        String version = versionOf(cell);
        Map<String, Object> header = Json.object(cell, "header");
        if (header == null) {
            throw new CellException.Malformed("missing header");
        }

        // §4.1: absence of header_hash is a rejection, not licence to skip the
        // checks. Guarding this block on its own presence would mean deleting
        // one field disables the header, ciphertext and signature checks
        // together.
        String headerHash = Json.string(cell, "header_hash");
        if (headerHash == null || headerHash.isEmpty()) {
            throw new CellException.Integrity("header_hash is missing");
        }
        byte[] headerBytes = serializeHeader(header, version);
        if (!CellCrypto.encodeB64(CellCrypto.sha256(headerBytes)).equals(headerHash)) {
            throw new CellException.Integrity("header may be tampered");
        }

        Map<String, Object> payload = Json.object(cell, "payload");
        if (payload == null) {
            payload = Json.object(cell, "encrypted_body");
        }
        String ctB64 = payload == null ? null : Json.string(payload, "ciphertext");
        if (ctB64 == null && payload != null) {
            ctB64 = Json.string(payload, "ct");
        }

        boolean payloadHashOk = false;
        String expectedPayloadHash = Json.string(header, "payload_hash");
        if (expectedPayloadHash != null) {
            if (ctB64 == null) {
                throw new CellException.Malformed(
                        "header commits to a ciphertext that is absent");
            }
            byte[] ct = CellCrypto.decodeB64(ctB64, "ciphertext");
            if (!CellCrypto.encodeB64(CellCrypto.sha256(ct)).equals(expectedPayloadHash)) {
                throw new CellException.Integrity("ciphertext may be tampered");
            }
            payloadHashOk = true;
        }

        boolean signed = false;
        String signerFingerprint = null;
        String sigB64 = Json.string(cell, "header_sig");
        String keyB64 = Json.string(cell, "header_sig_key");
        if (sigB64 != null && keyB64 != null) {
            byte[] spkiDer = CellCrypto.decodeB64(keyB64, "header_sig_key");
            CellCrypto.ecdsaVerify(CellCrypto.parseSpki(spkiDer),
                    CellCrypto.decodeB64(sigB64, "header_sig"), headerBytes);
            signed = true;
            // Trust anchors on the key's real fingerprint, never on
            // header_sig_by, which the signer writes about themselves.
            signerFingerprint = CellCrypto.fingerprint(spkiDer);
        }

        if (expectedSigner != null) {
            if (!signed) {
                throw new CellException.Signature("expected a cell signed by " + expectedSigner
                        + ", but it carries no signature (removal is undetectable — see spec §4.1)");
            }
            if (!expectedSigner.equals(signerFingerprint)) {
                throw new CellException.Signature("cell is signed by " + signerFingerprint
                        + ", not the expected " + expectedSigner);
            }
        }
        return new VerifyResult(version, payloadHashOk, signed, signerFingerprint,
                Json.string(cell, "header_sig_by"));
    }

    // ─── Opening ────────────────────────────────────────────────────────────

    /** A successfully opened cell. */
    public record OpenResult(
            byte[] data,
            String filename,
            String contentType,
            Object meta,
            String usedRecipient,
            boolean signed,
            String signerFingerprint,
            String claimedSigner,
            Lifetime lifetime) {}

    /** Key material and policy for {@link #open}. */
    public static final class OpenOptions {
        public List<KeyRecord> keys = new ArrayList<>();
        public List<String> passphrases = new ArrayList<>();
        /**
         * Maps a base64 {@code credential_id} to its 32-byte WebAuthn PRF
         * output. Entries with no supplied output are skipped, which is
         * conforming.
         */
        public Map<String, byte[]> prfOutputs = new HashMap<>();
        /** Overrides the clock for the advisory gates. */
        public Long now;
        /**
         * Skip the §8.1 gates. This is not a bypass of a security control: those
         * gates are advisory <b>by specification</b>, unenforceable against
         * anyone holding a key, and this field documents that honestly rather
         * than pretending otherwise.
         */
        public boolean ignoreAdvisory;
        /** A fingerprint learned out of band that the cell must be signed by. */
        public String expectedSigner;
    }

    /**
     * Open a cell and return its plaintext.
     *
     * <p>Verification order is normative (§10) and this follows it: the advisory
     * lifetime gates, then {@code header_hash}, {@code payload_hash} and
     * {@code header_sig} — all of which need no key — and only then any
     * access-map work. An opener that unwraps first performs a decryption under
     * a header it has not authenticated, and makes the user pay a
     * 600,000-iteration PBKDF2 derivation or a hardware touch on behalf of a
     * cell it is about to reject.
     */
    public static OpenResult open(Map<String, Object> cell, OpenOptions options) {
        OpenOptions opts = options == null ? new OpenOptions() : options;
        String version = versionOf(cell);
        boolean isLegacy = Json.string(cell, "version") == null
                && Json.string(cell, "cd_version") != null;
        long now = opts.now != null ? opts.now : KeyRecord.now();

        // Step 0: advisory gates. Cheapest of all, and they need nothing but the clock.
        Map<String, Object> header = Json.object(cell, "header");
        Lifetime lifetime = Lifetime.read(header == null ? null : Json.object(header, "lifetime"));
        if (lifetime != null && !opts.ignoreAdvisory) {
            if ("timed_release".equals(lifetime.type()) && lifetime.releaseAt() != null
                    && lifetime.releaseAt() > now) {
                throw new CellException.Lifetime(
                        "timed release — unlocks " + formatTimestamp(lifetime.releaseAt()));
            }
            if (lifetime.retainUntil() != null && lifetime.retainUntil() < now) {
                throw new CellException.Lifetime(
                        "retention period ended " + formatTimestamp(lifetime.retainUntil()));
            }
        }
        // Note disposal is never consulted: a passed disposal date describes the
        // operator's retention schedule, not the recipient's permission (§8.2).

        // Steps 1-3: integrity and authenticity, before any key material is touched.
        VerifyResult verified = null;
        if (!isLegacy) {
            verified = verify(cell, opts.expectedSigner);
        } else if (opts.expectedSigner != null) {
            throw new CellException.Signature("legacy v2.x cells carry no signature to check");
        }

        if (header == null) {
            header = new LinkedHashMap<>();
        }
        List<Object> accessMap = Json.array(header, "access_map");
        if (accessMap == null) {
            accessMap = Json.array(cell, "recipients");
        }
        if (accessMap == null) {
            accessMap = Collections.emptyList();
        }
        Map<String, Object> payload = Json.object(cell, "payload");
        if (payload == null) {
            payload = Json.object(cell, "encrypted_body");
        }
        if (payload == null) {
            throw new CellException.Malformed("payload is missing");
        }
        String ivB64 = Json.string(payload, "iv");
        String ctB64 = Json.string(payload, "ciphertext");
        if (ctB64 == null) {
            ctB64 = Json.string(payload, "ct");
        }
        if (ivB64 == null || ctB64 == null) {
            throw new CellException.Malformed("payload is missing iv or ciphertext");
        }
        int required = (int) Math.max(1, Json.integer(Json.object(header, "threshold"), "required", 1));

        // Step 4: recover the CEK.
        byte[] cek;
        String usedRecipient;
        if (required > 1) {
            List<Gf256.Share> shares = new ArrayList<>(required);
            for (int index = 0; index < accessMap.size() && shares.size() < required; index++) {
                Map<String, Object> entry = Json.asObject(accessMap.get(index));
                // A wrong key here says nothing about the next entry.
                byte[] material = tryUnwrap(entry, opts);
                if (material != null) {
                    int x = (int) Json.integer(entry, "share_index", index + 1);
                    shares.add(new Gf256.Share(x, material));
                }
            }
            if (shares.size() < required) {
                throw new CellException.QuorumNotMet(required, shares.size());
            }
            cek = Gf256.combine(shares);
            usedRecipient = shares.size() + "-of-" + accessMap.size() + " quorum";
        } else {
            byte[] material = null;
            String label = "";
            for (Object entryValue : accessMap) {
                Map<String, Object> entry = Json.asObject(entryValue);
                material = tryUnwrap(entry, opts);
                if (material != null) {
                    label = orEmpty(Json.string(entry, "label"));
                    break;
                }
            }
            if (material == null) {
                throw new CellException.NoMatchingKey();
            }
            cek = material;
            usedRecipient = label;
        }

        byte[] plain;
        try {
            byte[] aad = isLegacy ? null : cellAad(header, version);
            byte[] compressed = CellCrypto.aesGcmDecrypt(cek,
                    CellCrypto.decodeB64(ivB64, "iv"),
                    CellCrypto.decodeB64(ctB64, "ciphertext"), aad);
            plain = CellCrypto.gzipDecompress(compressed);
        } finally {
            CellCrypto.wipe(cek);
        }

        boolean signed = verified != null && verified.signed();
        String signerFingerprint = verified == null ? null : verified.signerFingerprint();
        String claimedSigner = verified == null ? null : verified.claimedSigner();

        // Manifest-prefixed payload (§5), or a legacy cell with plaintext metadata.
        if (cell.containsKey("original_filename")) {
            return new OpenResult(plain,
                    orDefault(Json.string(cell, "original_filename"), "decrypted"),
                    orDefault(Json.string(cell, "content_type"), "application/octet-stream"),
                    null, usedRecipient, signed, signerFingerprint, claimedSigner, lifetime);
        }
        if (plain.length < 4) {
            throw new CellException.Malformed("payload too short to hold a manifest length");
        }
        int manifestLength = ByteBuffer.wrap(plain, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (manifestLength < 0 || 4 + manifestLength > plain.length) {
            throw new CellException.Malformed("manifest length runs past the plaintext");
        }
        Map<String, Object> manifest =
                Json.asObject(Json.parse(Arrays.copyOfRange(plain, 4, 4 + manifestLength)));
        return new OpenResult(
                Arrays.copyOfRange(plain, 4 + manifestLength, plain.length),
                orDefault(Json.string(manifest, "filename"), "decrypted"),
                orDefault(Json.string(manifest, "content_type"), "application/octet-stream"),
                manifest.get("meta"), usedRecipient, signed, signerFingerprint, claimedSigner,
                lifetime);
    }

    /**
     * Attempt one access-map entry with whatever material was supplied.
     *
     * <p>Returns null rather than throwing: a wrong key for this entry says
     * nothing about the next one.
     */
    private static byte[] tryUnwrap(Map<String, Object> entry, OpenOptions opts) {
        Map<String, Object> wrapped = Json.object(entry, "wrapped_cek");
        if (wrapped == null) {
            return null;
        }
        String method = Json.string(entry, "method");
        if (method == null) {
            return null;
        }
        String ct = Json.string(wrapped, "ct");
        if (ct == null) {
            return null;
        }

        switch (method) {
            case "ecdh-p256" -> {
                String ephSpki = Json.string(wrapped, "eph_spki");
                if (ephSpki == null) {
                    return null;
                }
                PublicKey ephemeral = CellCrypto.parseSpki(
                        CellCrypto.decodeB64(ephSpki, "eph_spki"));
                String saltB64 = Json.string(wrapped, "hkdf_salt");

                // Match by fingerprint first so a cell addressed to ten
                // recipients does not run ten ECDH exchanges. Fall back to
                // trying everything, because the fingerprint is a hint and a
                // cell may omit or mangle it.
                String wanted = Json.string(entry, "fingerprint");
                List<KeyRecord> ordered = new ArrayList<>();
                for (KeyRecord key : opts.keys) {
                    if (key.privateKey() == null) {
                        continue;
                    }
                    if (wanted != null && wanted.equals(key.fingerprint())) {
                        ordered.add(0, key);
                    } else {
                        ordered.add(key);
                    }
                }
                for (KeyRecord key : ordered) {
                    try {
                        byte[] shared =
                                CellCrypto.ecdhSharedSecret(key.privateKey(), ephemeral);
                        byte[] wrappingKey;
                        if (saltB64 != null && !saltB64.isEmpty()) {
                            wrappingKey = CellCrypto.hkdf(shared,
                                    CellCrypto.decodeB64(saltB64, "hkdf_salt"),
                                    CellCrypto.HKDF_INFO, 32);
                        } else {
                            // Pre-spec legacy v2.0: the raw ECDH output
                            // truncated to 32 bytes, with no HKDF at all (§12).
                            // No conforming writer may produce this shape.
                            wrappingKey = Arrays.copyOf(shared, 32);
                        }
                        byte[] material = CellCrypto.aesKeyUnwrap(wrappingKey,
                                CellCrypto.decodeB64(ct, "ct"));
                        CellCrypto.wipe(wrappingKey);
                        return material;
                    } catch (CellException e) {
                        // try the next key
                    }
                }
                return null;
            }
            case "pbkdf2" -> {
                String saltB64 = Json.string(wrapped, "salt");
                if (saltB64 == null) {
                    return null;
                }
                byte[] salt = CellCrypto.decodeB64(saltB64, "salt");
                int iterations = (int) Json.integer(wrapped, "iterations",
                        CellCrypto.PBKDF2_ITERATIONS);
                if (iterations <= 0) {
                    iterations = CellCrypto.PBKDF2_ITERATIONS;
                }
                for (String passphrase : opts.passphrases) {
                    try {
                        byte[] wrappingKey =
                                CellCrypto.derivePassphraseKey(passphrase, salt, iterations);
                        byte[] material = CellCrypto.aesKeyUnwrap(wrappingKey,
                                CellCrypto.decodeB64(ct, "ct"));
                        CellCrypto.wipe(wrappingKey);
                        return material;
                    } catch (CellException e) {
                        // try the next passphrase
                    }
                }
                return null;
            }
            case "yubikey-prf" -> {
                String credentialId = Json.string(wrapped, "credential_id");
                byte[] output = credentialId == null ? null : opts.prfOutputs.get(credentialId);
                if (output == null) {
                    return null; // no token here; skipping is conforming
                }
                try {
                    return CellCrypto.aesKeyUnwrap(output, CellCrypto.decodeB64(ct, "ct"));
                } catch (CellException e) {
                    return null;
                }
            }
            default -> {
                return null;
            }
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private static String versionOf(Map<String, Object> cell) {
        String version = Json.string(cell, "version");
        if (version != null) {
            if (!SUPPORTED_VERSIONS.contains(version)) {
                throw new CellException.UnsupportedVersion(version);
            }
            return version;
        }
        String legacy = Json.string(cell, "cd_version");
        if (legacy != null) {
            return legacy; // legacy v2.x (§12)
        }
        throw new CellException.UnsupportedVersion("(absent)");
    }

    private static String formatTimestamp(long seconds) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'")
                .withZone(ZoneOffset.UTC)
                .format(Instant.ofEpochSecond(seconds));
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }
}
