// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic primitives — spec §6, §14.
 *
 * <p>The JDK supplies almost everything, including the two primitives that gave
 * other ports trouble: {@code AESWrap} (which Go had to implement from RFC 3394)
 * and {@code SHA256withECDSAinP1363Format} (which Go and Python had to convert
 * to and from DER by hand). The one gap is HKDF, which only arrives as
 * {@code javax.crypto.KDF} in JDK 24 — so it is implemented here from
 * {@code HmacSHA256}, which is all RFC 5869 actually is.
 */
public final class CellCrypto {

    private CellCrypto() {}

    /** Fixed info string for the ECDH key-wrap derivation (§6.1). */
    public static final byte[] HKDF_INFO =
            "cellular-defense-cek-wrap-v1".getBytes(StandardCharsets.UTF_8);
    /** Iteration count for passphrase entries (§6.2). */
    public static final int PBKDF2_ITERATIONS = 600_000;
    /** Ceiling on the count read from a file: header_hash is unkeyed, so an edited entry could otherwise stall the opener. */
    public static final int PBKDF2_MAX_ITERATIONS = 10_000_000;
    /** AES-GCM nonce length in bytes. */
    public static final int IV_LENGTH = 12;
    /** AES-GCM tag length in bits. Must be stated explicitly — see {@link #aesGcmEncrypt}. */
    public static final int GCM_TAG_BITS = 128;
    /** Content encryption key length in bytes. */
    public static final int CEK_LENGTH = 32;
    /**
     * Cap on gzip expansion. The spec sets no limit; the reference caps at 2 GiB.
     * A few KB of crafted gzip expands to many GB, and an opener that streams it
     * into memory is a denial of service needing no key at all.
     */
    public static final long MAX_DECOMPRESSED = 2L * 1024 * 1024 * 1024;

    private static final SecureRandom RANDOM = new SecureRandom();

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new CellException("SHA-256 unavailable", e);
        }
    }

    /** {@code SHA-256(SPKI)[..8]} as 16 lowercase hex characters — spec §13.3. */
    public static String fingerprint(byte[] spkiDer) {
        byte[] digest = sha256(spkiDer);
        StringBuilder out = new StringBuilder(16);
        for (int i = 0; i < 8; i++) {
            out.append(String.format("%02x", digest[i]));
        }
        return out.toString();
    }

    public static byte[] randomBytes(int n) {
        byte[] buf = new byte[n];
        RANDOM.nextBytes(buf);
        return buf;
    }

    // ─── Binary field encoding — spec §4.0 ──────────────────────────────────

    /**
     * Emit standard base64 with padding, the only form this library writes.
     *
     * <p>It is not base64url: {@code atob()} throws on {@code -} and {@code _},
     * so a base64url cell is unparseable by the reference rather than merely
     * non-canonical.
     */
    public static String encodeB64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Decode standard base64, tolerating the base64url alphabet and missing
     * padding on input, as §4.0's SHOULD asks.
     */
    public static byte[] decodeB64(String text, String field) {
        if (text == null) {
            throw new CellException.Malformed(field + " is missing");
        }
        String normalized = text.replace('-', '+').replace('_', '/');
        while (normalized.length() % 4 != 0) {
            normalized += "=";
        }
        try {
            return Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            throw new CellException.Malformed(field + " is not valid base64", e);
        }
    }

    // ─── Compression — spec §5 ──────────────────────────────────────────────

    /**
     * gzip {@code data}.
     *
     * <p>The reference uses {@code CompressionStream('gzip')}, whose output is
     * not byte-identical to any particular zlib configuration and need not be:
     * the format commits to the ciphertext, and gzip framing is decided before
     * encryption. Two conforming implementations sealing the same file produce
     * different bytes for this reason alone and both are correct.
     */
    public static byte[] gzipCompress(byte[] data) {
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                GZIPOutputStream gzip = new GZIPOutputStream(buffer)) {
            gzip.write(data);
            gzip.finish();
            return buffer.toByteArray();
        } catch (Exception e) {
            throw new CellException.Malformed("gzip failed", e);
        }
    }

    /**
     * Decompress exactly one gzip member, refusing to exceed
     * {@link #MAX_DECOMPRESSED}.
     *
     * <p>Nothing may follow the member: not a second member, not trailing bytes.
     * Implementations once disagreed on both (some joined members, some read
     * only the first; some ignored trailing bytes, some refused), so one file
     * opened as different documents in different programs. GZIPInputStream joins
     * members and silently drops trailing bytes that do not look like a header,
     * so the header and trailer are read here and the deflate data in between
     * goes to an {@link Inflater}, which reports exactly what it left unread.
     */
    public static byte[] gzipDecompress(byte[] data) {
        int start = gzipHeaderEnd(data);
        int end = data.length - 8; // CRC-32 and size, little-endian
        if (end <= start) {
            throw new CellException.Malformed("truncated gzip stream");
        }
        Inflater inflater = new Inflater(true);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            inflater.setInput(data, start, data.length - start);
            byte[] chunk = new byte[65536];
            long total = 0;
            while (!inflater.finished()) {
                int n = inflater.inflate(chunk);
                if (n == 0 && !inflater.finished()) {
                    throw new CellException.Malformed("truncated gzip stream");
                }
                total += n;
                if (total > MAX_DECOMPRESSED) {
                    throw new CellException.Malformed("decompressed size exceeds safety limit");
                }
                out.write(chunk, 0, n);
            }
            int left = inflater.getRemaining();
            if (left > 8) {
                throw new CellException.Malformed("data after the end of the gzip member — refusing");
            }
            if (left < 8) {
                throw new CellException.Malformed("truncated gzip stream");
            }
            byte[] plain = out.toByteArray();
            CRC32 crc = new CRC32();
            crc.update(plain);
            if (crc.getValue() != le32(data, end) || (plain.length & 0xffffffffL) != le32(data, end + 4)) {
                throw new CellException.Malformed("gzip checksum or size mismatch");
            }
            return plain;
        } catch (DataFormatException e) {
            throw new CellException.Malformed("payload is not a valid gzip stream", e);
        } catch (java.io.IOException e) {
            throw new CellException.Malformed("payload is not a valid gzip stream", e);
        } finally {
            inflater.end();
        }
    }

    private static long le32(byte[] b, int at) {
        return (b[at] & 0xffL) | (b[at + 1] & 0xffL) << 8 | (b[at + 2] & 0xffL) << 16
                | (b[at + 3] & 0xffL) << 24;
    }

    /** Where the deflate data starts after a gzip member header (RFC 1952 §2.3). */
    private static int gzipHeaderEnd(byte[] b) {
        if (b.length < 10 || (b[0] & 0xff) != 0x1f || (b[1] & 0xff) != 0x8b || b[2] != 8) {
            throw new CellException.Malformed("payload is not a valid gzip stream — bad header");
        }
        int flg = b[3] & 0xff;
        if ((flg & 0xe0) != 0) {
            throw new CellException.Malformed("gzip header has reserved flags set");
        }
        int i = 10;
        if ((flg & 0x04) != 0) { // FEXTRA
            if (i + 2 > b.length) {
                throw new CellException.Malformed("truncated gzip header");
            }
            i += 2 + ((b[i] & 0xff) | (b[i + 1] & 0xff) << 8);
        }
        for (int f : new int[] {0x08, 0x10}) { // FNAME, FCOMMENT: zero-terminated
            if ((flg & f) == 0) {
                continue;
            }
            while (i < b.length && b[i] != 0) {
                i++;
            }
            i++;
        }
        if ((flg & 0x02) != 0) { // FHCRC: low 16 bits of the header's CRC-32
            if (i + 2 > b.length) {
                throw new CellException.Malformed("truncated gzip header");
            }
            CRC32 crc = new CRC32();
            crc.update(b, 0, i);
            if ((crc.getValue() & 0xffff) != ((b[i] & 0xff) | (b[i + 1] & 0xff) << 8)) {
                throw new CellException.Malformed("gzip header checksum mismatch");
            }
            i += 2;
        }
        if (i > b.length) {
            throw new CellException.Malformed("truncated gzip header");
        }
        return i;
    }

    // ─── Content encryption — AES-256-GCM, spec §4.3 ────────────────────────

    /**
     * Encrypt with AES-256-GCM. Returns {@code ciphertext || tag}.
     *
     * <p>The 128-bit tag is appended to the ciphertext, matching WebCrypto. Java
     * will not do that unless {@link GCMParameterSpec} is given the tag length
     * explicitly — this is the JDK's version of the trap §4.1 warns about for
     * signatures, and a shorter tag would produce cells nothing else can open.
     */
    public static byte[] aesGcmEncrypt(byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) {
        if (cek.length != CEK_LENGTH) {
            throw new CellException.Malformed("CEK must be " + CEK_LENGTH + " bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CellException.Malformed("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypt and verify. A tag failure here is equally an AAD mismatch: the two
     * are indistinguishable by design (§4.4).
     */
    public static byte[] aesGcmDecrypt(byte[] cek, byte[] iv, byte[] ciphertext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CellException.Decryption();
        }
    }

    // ─── HKDF-SHA256 (RFC 5869) ─────────────────────────────────────────────

    /**
     * HKDF-SHA256, extract-then-expand.
     *
     * <p>The one primitive the JDK does not provide before 24
     * ({@code javax.crypto.KDF}). Fifteen lines of HMAC, and RFC 5869 has test
     * vectors — worth writing rather than pulling in a provider.
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // Extract.
            mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            // Expand.
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] out = new byte[length];
            byte[] block = new byte[0];
            int position = 0;
            for (int counter = 1; position < length; counter++) {
                mac.update(block);
                mac.update(info);
                mac.update((byte) counter);
                block = mac.doFinal();
                int take = Math.min(block.length, length - position);
                System.arraycopy(block, 0, out, position, take);
                position += take;
            }
            return out;
        } catch (Exception e) {
            throw new CellException("HKDF failed", e);
        }
    }

    // ─── AES Key Wrap ───────────────────────────────────────────────────────

    /** Wrap under AES-KW. The JDK provides this as {@code AESWrap}. */
    public static byte[] aesKeyWrap(byte[] kek, byte[] keyMaterial) {
        try {
            Cipher cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
            return cipher.wrap(new SecretKeySpec(keyMaterial, "AES"));
        } catch (Exception e) {
            throw new CellException.Malformed("AES-KW wrap failed", e);
        }
    }

    /**
     * Unwrap under AES-KW.
     *
     * <p>A failure is the RFC 3394 integrity check value not matching, which is
     * how a wrong wrapping key is detected at all — so it maps to
     * {@link CellException.NoMatchingKey} rather than a malformed-input error.
     */
    public static byte[] aesKeyUnwrap(byte[] kek, byte[] wrapped) {
        try {
            Cipher cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
            SecretKey key = (SecretKey) cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            return key.getEncoded();
        } catch (Exception e) {
            throw new CellException.NoMatchingKey();
        }
    }

    // ─── CEK wrapping — ECDH P-256 → HKDF-SHA256 → AES-KW, spec §6.1 ────────

    /** Derive the raw ECDH shared secret: the X coordinate of the shared point. */
    public static byte[] ecdhSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            // WebCrypto's deriveBits(..., 256) on P-256 yields exactly this.
            // Neither side applies a KDF here — HKDF is the caller's next step.
            return agreement.generateSecret();
        } catch (Exception e) {
            throw new CellException.Malformed("ECDH failed", e);
        }
    }

    // ─── CEK wrapping — PBKDF2, spec §6.2 ───────────────────────────────────

    /**
     * PBKDF2-HMAC-SHA256 over the passphrase.
     *
     * <p>No Unicode normalization is applied — WebCrypto has no opinion about
     * text encoding and the reference feeds it
     * {@code TextEncoder().encode(passphrase)}. Composed and decomposed accents
     * are therefore two different passphrases, on every implementation.
     *
     * <p>{@link PBEKeySpec} takes a {@code char[]}, and SunJCE encodes it as
     * UTF-8 for the HMAC-SHA2 variants, which is what makes this interoperate.
     * A test pins that against a value computed by the Python port rather than
     * trusting it.
     */
    public static byte[] derivePassphraseKey(String passphrase, byte[] salt, int iterations) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, iterations, 256);
            try {
                return factory.generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (Exception e) {
            throw new CellException("PBKDF2 failed", e);
        }
    }

    // ─── Key encoding and ECDSA — spec §4.1, §13 ────────────────────────────

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new CellException("P-256 key generation failed", e);
        }
    }

    public static PublicKey parseSpki(byte[] der) {
        try {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CellException.Malformed("invalid SPKI public key", e);
        }
    }

    public static PrivateKey parsePkcs8(byte[] der) {
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CellException.Malformed("invalid PKCS#8 private key", e);
        }
    }

    /**
     * Sign with ECDSA-SHA256, returning raw {@code r ‖ s}.
     *
     * <p>Spec §4.1 names DER-vs-P1363 the single most likely point of failure
     * outside a browser. Java has had a P1363 signature format since JDK 11, so
     * it is a non-issue here — but note that plain {@code "SHA256withECDSA"}
     * produces DER, and swapping the two silently yields signatures nothing else
     * can verify.
     */
    public static byte[] ecdsaSign(PrivateKey privateKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new CellException("ECDSA signing failed", e);
        }
    }

    /**
     * Verify a raw 64-byte {@code r ‖ s} signature.
     *
     * <p>A signature of any other length is refused outright rather than decoded
     * as a courtesy: accepting DER here would interoperate with nothing and hide
     * the bug until a browser saw the cell.
     */
    public static void ecdsaVerify(PublicKey publicKey, byte[] rawSig, byte[] data) {
        if (rawSig.length != 64) {
            throw new CellException.Malformed(
                    "header_sig must be 64 bytes of raw r||s (IEEE P1363), got " + rawSig.length
                            + "; a DER-encoded signature is not accepted (spec §4.1)");
        }
        boolean valid;
        try {
            Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
            signature.initVerify(publicKey);
            signature.update(data);
            valid = signature.verify(rawSig);
        } catch (Exception e) {
            throw new CellException.Signature("header signature invalid — cell may be forged");
        }
        if (!valid) {
            throw new CellException.Signature("header signature invalid — cell may be forged");
        }
    }

    /** Constant-time comparison, for the one place a timing signal could matter. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Best-effort zeroization. The JVM may have copied the bytes during
     * boxing or garbage collection and will not say so; this overwrites what we
     * can reach and no more.
     */
    public static void wipe(byte[] buffer) {
        Arrays.fill(buffer, (byte) 0);
    }

    // ─── CEK wrapping — Argon2id, spec §6.5 (v1.4) ──────────────────────────

    /** Written by default: RFC 9106 §4's second recommended option (m KiB, t, p). */
    public static final int[] ARGON2_DEFAULTS = {65536, 3, 4};
    private static final int ARGON2_M_MIN = 19456;
    private static final int ARGON2_M_MAX = 1048576;
    private static final int ARGON2_ONE_PASS_MIN_M = 47104;

    /**
     * Refuse parameters outside the bounds of §6.5, exactly as the reference
     * does: below the floor the passphrase is barely protected; above the
     * ceiling a hostile cell can exhaust the opener's memory or time.
     */
    /** Read and check an entry's m, t and p (§6.5); returns {m, t, p}. */
    public static int[] argon2Params(Map<String, Object> wrapped) {
        long[] v = new long[3];
        String[] keys = {"m", "t", "p"};
        for (int i = 0; i < 3; i++) {
            Long n = Json.integral(wrapped == null ? null : wrapped.get(keys[i]));
            if (n == null) {
                throw new CellException.Malformed("Argon2id parameters out of range — refusing (§6.5)");
            }
            v[i] = n;
        }
        argon2Check(v[0], v[1], v[2]);
        return new int[] {(int) v[0], (int) v[1], (int) v[2]};
    }

    /**
     * An entry's iteration count: absent, null or 0 means the default; anything
     * else must be a whole number in 1…10,000,000.
     */
    public static int pbkdf2Iterations(Map<String, Object> wrapped) {
        Object raw = wrapped == null ? null : wrapped.get("iterations");
        if (raw == null) {
            return PBKDF2_ITERATIONS;
        }
        Long n = Json.integral(raw);
        if (n != null && n == 0) {
            return PBKDF2_ITERATIONS;
        }
        if (n == null || n < 1 || n > PBKDF2_MAX_ITERATIONS) {
            throw new CellException.Malformed("PBKDF2 iteration count out of range — refusing");
        }
        return (int) (long) n;
    }

    // ─── Passphrase work bound — spec §6, §6.2, §6.5 ───────────────────────
    //
    // The limits above bound one entry. header_hash is unkeyed, so anyone who
    // can rewrite a file can add entries, each within those limits, and an
    // opener would derive a key for every one. So one open is bounded too:
    // passphrase entries are tried cheapest first, and the opener stops before
    // its key-derivation work would pass that of one maximum-parameter entry.
    // Any single entry within the limits still opens. Work is counted in
    // integers, as in the reference: PBKDF2 = iterations × 2^24,
    // Argon2id = m × t × 10^7, limit = 10^7 × 2^24.

    private static final long ARGON2_MAX_WORK = (long) ARGON2_M_MAX * 16; // 2^24

    /** The passphrase work one open may spend (see {@link #kdfWork}). */
    public static final long MAX_KDF_WORK = PBKDF2_MAX_ITERATIONS * ARGON2_MAX_WORK;

    /**
     * Work for one derivation against {@code entry}; 0 when its parameters are
     * refused (the unwrap then fails without deriving anything).
     */
    public static long kdfWork(Map<String, Object> entry) {
        Map<String, Object> wrapped = Json.object(entry, "wrapped_cek");
        String method = Json.string(entry, "method");
        try {
            if ("pbkdf2".equals(method)) {
                return pbkdf2Iterations(wrapped) * ARGON2_MAX_WORK;
            }
            if ("argon2id".equals(method)) {
                int[] mtp = argon2Params(wrapped);
                return (long) mtp[0] * mtp[1] * PBKDF2_MAX_ITERATIONS;
            }
        } catch (CellException.Malformed e) {
            // out of range: no derivation runs
        }
        return 0;
    }

    public static void argon2Check(long m, long t, long p) {
        if (m < ARGON2_M_MIN || m > ARGON2_M_MAX || t < 1 || t > 16 || p < 1 || p > 16) {
            throw new CellException.Malformed("Argon2id parameters out of range — refusing (§6.5)");
        }
        if (t == 1 && m < ARGON2_ONE_PASS_MIN_M) {
            throw new CellException.Malformed(
                    "Argon2id with one pass needs at least 46 MiB — refusing (§6.5)");
        }
    }

    /**
     * Argon2id v0x13, 32-byte tag, over the UTF-8 of the passphrase's NFC form.
     * Unlike PBKDF2 entries (§6.2), v1.4 normalizes: a passphrase typed with a
     * composed é on one machine and a decomposed é on another is one passphrase.
     */
    public static byte[] argon2Key(String passphrase, byte[] salt, int m, int t, int p) {
        byte[] secret = java.text.Normalizer.normalize(passphrase, java.text.Normalizer.Form.NFC)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var params = new org.bouncycastle.crypto.params.Argon2Parameters.Builder(
                org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id)
                .withVersion(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt).withIterations(t).withMemoryAsKB(m).withParallelism(p).build();
        var generator = new org.bouncycastle.crypto.generators.Argon2BytesGenerator();
        generator.init(params);
        byte[] key = new byte[32];
        generator.generateBytes(secret, key);
        wipe(secret);
        return key;
    }

    // ─── Padding — Padmé, spec §5.4 (v1.4) ──────────────────────────────────

    private static final int PAD_FLOOR = 512;

    /** Padmé (Nikitin et al., PETS 2019) with a 512-byte floor. */
    public static long padmeLength(long n) {
        if (n <= PAD_FLOOR) {
            return PAD_FLOOR;
        }
        int e = 63 - Long.numberOfLeadingZeros(n);     // floor(log2 n)
        int s = 64 - Long.numberOfLeadingZeros(e);     // floor(log2 e) + 1
        long step = 1L << (e - s);
        return (n + step - 1) / step * step;
    }

    /** {@code LE32(len(gz)) || gz || zeros} up to {@code padmeLength(4 + len(gz))}. */
    public static byte[] padBody(byte[] gz) {
        if (gz.length < 0 || (long) gz.length >= (1L << 32)) {
            throw new CellException.Malformed("body of 2^32 bytes or more is out of scope");
        }
        byte[] out = new byte[(int) padmeLength(4L + gz.length)];
        out[0] = (byte) gz.length;
        out[1] = (byte) (gz.length >>> 8);
        out[2] = (byte) (gz.length >>> 16);
        out[3] = (byte) (gz.length >>> 24);
        System.arraycopy(gz, 0, out, 4, gz.length);
        return out;
    }

    /** Inverse of {@link #padBody}: reject an overrunning length or non-zero padding. */
    public static byte[] unpadBody(byte[] body) {
        if (body.length < 4) {
            throw new CellException.Malformed("malformed padded body");
        }
        long n = (body[0] & 0xffL) | (body[1] & 0xffL) << 8 | (body[2] & 0xffL) << 16
                | (body[3] & 0xffL) << 24;
        if (4 + n > body.length) {
            throw new CellException.Malformed("malformed padded body — length exceeds body");
        }
        // Exactly the Padmé length: any other would let a writer pad to a size of
        // its choosing, and give a crafted body room that a conforming one lacks.
        if (body.length != padmeLength(4 + n)) {
            throw new CellException.Malformed("malformed padded body — not the Padmé length");
        }
        for (int i = (int) (4 + n); i < body.length; i++) {
            if (body[i] != 0) {
                throw new CellException.Malformed("malformed padded body — non-zero padding");
            }
        }
        return java.util.Arrays.copyOfRange(body, 4, (int) (4 + n));
    }
}
