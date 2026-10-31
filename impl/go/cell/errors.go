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

	// ErrSenderSignature is the v1.4 inner sender-signature equivalent of
	// ErrSignature (spec §4.5): the signature carried inside the encrypted
	// payload does not verify, or an expected signer was required and did not
	// match. Kept distinct from ErrSignature — both are checked the same way
	// (ECDSA over a SHA-256 digest), but a v1.4 cell carries no header_sig at
	// all, and a failure reported as "header signature invalid" sent readers
	// looking at the wrong field of the spec (found in pen test, 2026-10-31).
	ErrSenderSignature = errors.New("sender signature invalid")

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

// senderSigErr reports a v1.4 inner sender-signature failure under its own
// message, while still satisfying errors.Is(err, ErrSignature): the shared
// conformance manifest's reject_reason for this case ("signature-invalid") is
// explicitly not normative across languages, but this package's own tests
// and any caller written against the older, broader sentinel still need to
// match. A nested %w (ErrSenderSignature, then ErrSignature) would work for
// errors.Is but prints both messages concatenated; this keeps one message.
type senderSigErr struct{ msg string }

func (e *senderSigErr) Error() string { return e.msg }

func (e *senderSigErr) Is(target error) bool {
	return target == ErrSenderSignature || target == ErrSignature
}

func senderSignatureError(msg string) error { return &senderSigErr{msg: msg} }
