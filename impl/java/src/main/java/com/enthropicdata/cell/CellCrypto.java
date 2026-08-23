// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.io.ByteArrayInputStream;
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
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
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

    /** Decompress a gzip stream, refusing to exceed {@link #MAX_DECOMPRESSED}. */
    public static byte[] gzipDecompress(byte[] data) {
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(data));
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[65536];
            long total = 0;
            int read;
            while ((read = gzip.read(chunk)) > 0) {
                total += read;
                if (total > MAX_DECOMPRESSED) {
                    throw new CellException.Malformed("decompressed size exceeds safety limit");
                }
                out.write(chunk, 0, read);
            }
            return out.toByteArray();
        } catch (CellException e) {
            throw e;
        } catch (Exception e) {
            throw new CellException.Malformed("payload is not a valid gzip stream", e);
        }
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
}
