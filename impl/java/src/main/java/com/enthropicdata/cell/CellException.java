// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

/**
 * Every failure this library produces.
 *
 * <p>The subclasses exist because the distinctions matter to a caller: "this
 * file is not a cell I can read", "this cell has been tampered with" and "you
 * gave me the wrong key" call for three different responses, and the reference
 * implementation collapses all of them into {@code Error(string)}.
 *
 * <p>Unchecked, deliberately. A cell that fails to open is not an exceptional
 * condition a caller can usefully be forced to declare at every layer.
 */
public class CellException extends RuntimeException {

    public CellException(String message) {
        super(message);
    }

    public CellException(String message, Throwable cause) {
        super(message, cause);
    }

    /** {@code cell.version} is present but not in {@code Cell.SUPPORTED_VERSIONS} (§12). */
    public static class UnsupportedVersion extends CellException {
        public UnsupportedVersion(String version) {
            super("unsupported cell format version \"" + version
                    + "\" — update the app to open this cell");
        }
    }

    /** Structurally invalid: missing header, bad base64, truncated manifest. */
    public static class Malformed extends CellException {
        public Malformed(String message) {
            super("malformed cell: " + message);
        }

        public Malformed(String message, Throwable cause) {
            super("malformed cell: " + message, cause);
        }
    }

    /** {@code header_hash} or {@code payload_hash} mismatch, or a missing hash (§4.1, §10). */
    public static class Integrity extends CellException {
        public Integrity(String message) {
            super("integrity check failed — " + message);
        }
    }

    /** {@code header_sig} is present and does not verify, or an expected signer did not match. */
    public static class Signature extends CellException {
        public Signature(String message) {
            super(message);
        }
    }

    /**
     * An advisory lifetime gate refused the open (§8.1). Advisory means
     * advisory: a keyholder can bypass this and the specification says so.
     */
    public static class Lifetime extends CellException {
        public Lifetime(String message) {
            super(message);
        }
    }

    /** No access-map entry could be unwrapped with the material provided. */
    public static class NoMatchingKey extends CellException {
        public NoMatchingKey() {
            super("no matching key — check your key method and try again");
        }

        NoMatchingKey(String message) {
            super(message);
        }
    }

    /** Fewer than {@code threshold.required} shares were recovered (§7). */
    public static class QuorumNotMet extends NoMatchingKey {
        public QuorumNotMet(int needed, int unlocked) {
            super("quorum not met — need " + needed + ", unlocked " + unlocked);
        }
    }

    /**
     * The AES-GCM tag failed: the ciphertext or the AAD-bound metadata does not
     * match what was sealed (§4.4).
     */
    public static class Decryption extends CellException {
        public Decryption() {
            super("authentication failed — the ciphertext or the AAD-bound metadata "
                    + "(prev_hash/threshold/lifetime/policy) does not match what was sealed");
        }
    }

    /** A value cannot be serialized compatibly with the reference (§4.1.1). */
    public static class Canonicalization extends CellException {
        public Canonicalization(String message) {
            super("cannot canonicalize value: " + message);
        }
    }
}
