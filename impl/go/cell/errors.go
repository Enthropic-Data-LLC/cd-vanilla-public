// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import "errors"

// Sentinel errors, comparable with errors.Is. The distinctions matter to a
// caller: "this file is not a cell I can read", "this cell has been tampered
// with" and "you gave me the wrong key" call for three different responses,
// and the reference implementation collapses all of them into Error(string).
var (
	// ErrUnsupportedVersion is returned when cell.version is present but not in
	// SupportedVersions (spec §12).
	ErrUnsupportedVersion = errors.New("unsupported cell format version")

	// ErrMalformed covers structural failures: missing header, bad base64,
	// truncated manifest, a signature of the wrong length.
	ErrMalformed = errors.New("malformed cell")

	// ErrIntegrity is a header_hash or payload_hash mismatch, or a missing
	// header_hash (spec §4.1, §10).
	ErrIntegrity = errors.New("integrity check failed")

	// ErrSignature is returned when header_sig is present and does not verify,
	// or when an expected signer was required and did not match.
	ErrSignature = errors.New("header signature invalid")

	// ErrLifetime is an advisory lifetime gate refusing the open (spec §8.1).
	// Advisory means advisory: a keyholder can bypass this and the specification
	// says so.
	ErrLifetime = errors.New("lifetime gate refused")

	// ErrNoMatchingKey means no access-map entry could be unwrapped with the
	// material provided.
	ErrNoMatchingKey = errors.New("no matching key")

	// ErrQuorumNotMet means fewer than threshold.required shares were recovered.
	ErrQuorumNotMet = errors.New("quorum not met")

	// ErrDecryption is an AES-GCM tag failure: the ciphertext or the AAD-bound
	// metadata does not match what was sealed (spec §4.4).
	ErrDecryption = errors.New("authentication failed")

	// ErrCanonicalization means a value cannot be serialized compatibly with
	// the reference implementation (spec §4.1.1).
	ErrCanonicalization = errors.New("cannot canonicalize value")
)
