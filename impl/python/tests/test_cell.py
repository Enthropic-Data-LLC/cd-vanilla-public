# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Cell sealing and opening, with the negative cases carrying most of the weight.

A round-trip test proves only that the library agrees with itself. What a
conformance suite has to establish is that the *refusals* happen — that a
tampered AAD fails, that a downgraded version fails, that a missing hash is a
rejection rather than a licence to skip the checks.
"""

from __future__ import annotations

import copy
import json
import time
import unittest

from cellular_defense import (
    CELL_FORMAT_VERSION,
    DecryptionError,
    IntegrityError,
    KeyRecord,
    LifetimeError,
    MalformedCellError,
    NoMatchingKeyError,
    QuorumNotMetError,
    Recipient,
    SignatureError,
    UnsupportedVersionError,
    cell_create,
    cell_open,
    verify_cell,
)
from cellular_defense import crypto
from cellular_defense.canonical import canonical_bytes, js_stringify
from cellular_defense.cell import serialize_header
from cellular_defense.codec import b64decode, b64encode

DAY = 86400


def rehash(cell: dict) -> dict:
    """Recompute header_hash so a tampered cell passes step 1 of §10.

    Every "attacker edits the header" test needs this: header_hash is unkeyed,
    so an attacker who edits the header simply recomputes it. That is exactly
    why the AAD binding and the signature exist, and these tests are what
    demonstrate they are load-bearing rather than decorative.
    """
    cell["header_hash"] = b64encode(
        crypto.sha256(serialize_header(cell["header"], cell["version"]))
    )
    return cell


class CellTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.alice = KeyRecord.generate("Alice")
        cls.bob = KeyRecord.generate("Bob")

    def seal(self, data: bytes = b"payload", **kwargs) -> dict:
        kwargs.setdefault("recipients", [Recipient.for_key(self.alice)])
        recipients = kwargs.pop("recipients")
        return cell_create(data, kwargs.pop("filename", "f.txt"), recipients, **kwargs)


class TestRoundTrip(CellTestCase):
    def test_basic(self):
        cell = self.seal(b"hello", filename="hello.txt", content_type="text/plain")
        result = cell_open(cell, keys=[self.alice])
        self.assertEqual(result.data, b"hello")
        self.assertEqual(result.filename, "hello.txt")
        self.assertEqual(result.content_type, "text/plain")
        self.assertFalse(result.signed)

    def test_empty_file(self):
        cell = self.seal(b"", filename="empty")
        self.assertEqual(cell_open(cell, keys=[self.alice]).data, b"")

    def test_large_binary(self):
        data = bytes(range(256)) * 4096  # 1 MiB, incompressible enough to matter
        cell = self.seal(data)
        self.assertEqual(cell_open(cell, keys=[self.alice]).data, data)

    def test_unicode_filename_and_meta(self):
        cell = self.seal(b"x", filename="rapport-financiér-😀.pdf", meta={"note": "café"})
        result = cell_open(cell, keys=[self.alice])
        self.assertEqual(result.filename, "rapport-financiér-😀.pdf")
        self.assertEqual(result.meta, {"note": "café"})

    def test_filename_and_size_are_not_visible_in_the_cell(self):
        # §5: the manifest lives inside the ciphertext. If the filename appears
        # anywhere in the serialized cell, metadata confidentiality is broken.
        cell = self.seal(b"x" * 1000, filename="secret-merger-terms.pdf")
        self.assertNotIn("secret-merger-terms", json.dumps(cell))

    def test_multiple_recipients_each_open_independently(self):
        cell = self.seal(
            b"shared",
            recipients=[
                Recipient.for_key(self.alice),
                Recipient.for_key(self.bob),
                Recipient.passphrase_("hunter2"),
            ],
        )
        self.assertEqual(cell_open(cell, keys=[self.alice]).data, b"shared")
        self.assertEqual(cell_open(cell, keys=[self.bob]).data, b"shared")
        self.assertEqual(cell_open(cell, passphrases=["hunter2"]).data, b"shared")

    def test_reformatting_does_not_break_verification(self):
        # The whole point of canonicalization (§4.1.1): a cell that has been
        # pretty-printed or had its keys reordered in transit still verifies.
        cell = self.seal(b"x")
        reordered = json.loads(
            json.dumps(cell, sort_keys=True, indent=4), object_pairs_hook=dict
        )
        reordered["header"] = dict(reversed(list(reordered["header"].items())))
        verify_cell(reordered)
        self.assertEqual(cell_open(reordered, keys=[self.alice]).data, b"x")


class TestIntegrityRefusals(CellTestCase):
    def test_missing_header_hash_is_a_rejection(self):
        # §4.1: absence must not be treated as licence to skip the checks —
        # deleting one field would otherwise disable header, ciphertext and
        # signature verification together.
        cell = self.seal()
        del cell["header_hash"]
        with self.assertRaises(IntegrityError):
            cell_open(cell, keys=[self.alice])

    def test_header_hash_mismatch(self):
        cell = self.seal()
        cell["header"]["policy"]["copy_protection"] = "none"
        with self.assertRaises(IntegrityError):
            cell_open(cell, keys=[self.alice])

    def test_tampered_ciphertext_fails_payload_hash(self):
        cell = self.seal()
        raw = bytearray(b64decode(cell["payload"]["ciphertext"]))
        raw[0] ^= 0x01
        cell["payload"]["ciphertext"] = b64encode(bytes(raw))
        with self.assertRaises(IntegrityError):
            cell_open(cell, keys=[self.alice])

    def test_tampered_aad_metadata_fails_the_gcm_tag(self):
        # The attacker edits bound metadata AND recomputes the unkeyed
        # header_hash, so §10 steps 1-3 all pass. The AAD binding is the only
        # thing left, and it must catch this.
        cell = rehash(_mutate(self.seal(), lambda c: c["header"]["threshold"].update(required=1, of_total=9)))
        with self.assertRaises(DecryptionError):
            cell_open(cell, keys=[self.alice])

    def test_tampered_lifetime_fails_the_gcm_tag(self):
        cell = self.seal(lifetime={"type": "record", "advisory": {"retain_until": None}})
        cell["header"]["lifetime"]["advisory"]["minimum_atl"] = 99
        rehash(cell)
        with self.assertRaises(DecryptionError):
            cell_open(cell, keys=[self.alice])

    def test_version_downgrade_fails_the_gcm_tag(self):
        # §4.4: rewriting version to 1.0 would strip the AAD from the decrypt.
        # The ciphertext was produced *with* AAD, so the tag fails — an attacker
        # cannot re-encrypt without the CEK.
        cell = self.seal()
        cell["version"] = "1.0"
        rehash(cell)  # recomputed under 1.0's JSON.stringify serialization
        with self.assertRaises(DecryptionError):
            cell_open(cell, keys=[self.alice])

    def test_unknown_version_is_refused_with_a_clear_error(self):
        cell = self.seal()
        cell["version"] = "9.9"
        with self.assertRaises(UnsupportedVersionError):
            cell_open(cell, keys=[self.alice])

    def test_swapped_access_map_entry_is_caught(self):
        # access_map is not in the AAD (it does not exist at encryption time),
        # so header_hash is what covers it — and an attacker who recomputes the
        # hash is then caught by the signature, if there is one.
        cell = self.seal(sender=self.alice)
        other = self.seal(recipients=[Recipient.for_key(self.bob)])
        cell["header"]["access_map"] = other["header"]["access_map"]
        rehash(cell)
        with self.assertRaises(SignatureError):
            cell_open(cell, keys=[self.bob])


class TestSignatures(CellTestCase):
    def test_signed_cell_reports_the_real_fingerprint(self):
        cell = self.seal(sender=self.bob)
        result = cell_open(cell, keys=[self.alice])
        self.assertTrue(result.signed)
        self.assertEqual(result.signer_fingerprint, self.bob.fingerprint)

    def test_header_sig_by_is_not_trusted(self):
        # §4.1: header_sig_by is a self-asserted label. Changing it must not
        # change who the cell is attributed to.
        cell = self.seal(sender=self.bob)
        cell["header_sig_by"] = "Trust Me Inc"
        rehash(cell)
        result = cell_open(cell, keys=[self.alice])
        self.assertEqual(result.signer_fingerprint, self.bob.fingerprint)
        self.assertEqual(result.claimed_signer, "Trust Me Inc")
        with self.assertRaises(SignatureError):
            cell_open(cell, keys=[self.alice], expected_signer="deadbeefdeadbeef")

    def test_invalid_signature_is_refused(self):
        cell = self.seal(sender=self.bob)
        raw = bytearray(b64decode(cell["header_sig"]))
        raw[0] ^= 0xFF
        cell["header_sig"] = b64encode(bytes(raw))
        with self.assertRaises(SignatureError):
            cell_open(cell, keys=[self.alice])

    def test_forged_signature_key_is_refused(self):
        cell = self.seal(sender=self.bob)
        cell["header_sig_key"] = self.alice.spki
        with self.assertRaises(SignatureError):
            cell_open(cell, keys=[self.alice])

    def test_der_encoded_signature_is_refused(self):
        # §4.1's named trap: every general-purpose library produces DER by
        # default, and DER in header_sig must not verify.
        cell = self.seal(sender=self.bob)
        der = crypto.p1363_to_der(b64decode(cell["header_sig"]))
        cell["header_sig"] = b64encode(der)
        with self.assertRaises(MalformedCellError):
            cell_open(cell, keys=[self.alice])

    def test_stripped_signature_is_undetectable_but_expected_signer_catches_it(self):
        # §4.1: an attacker can delete the signature and the result is
        # byte-indistinguishable from a cell that was never signed. "Opened
        # without error" is therefore not evidence of authorship — only an
        # out-of-band expectation is.
        cell = self.seal(sender=self.bob)
        for key in ("header_sig", "header_sig_by", "header_sig_key"):
            cell[key] = None
        rehash(cell)
        self.assertFalse(cell_open(cell, keys=[self.alice]).signed)  # opens cleanly
        with self.assertRaises(SignatureError):
            cell_open(cell, keys=[self.alice], expected_signer=self.bob.fingerprint)


class TestAccessControl(CellTestCase):
    def test_wrong_key(self):
        cell = self.seal()
        with self.assertRaises(NoMatchingKeyError):
            cell_open(cell, keys=[self.bob])

    def test_wrong_passphrase(self):
        cell = self.seal(recipients=[Recipient.passphrase_("right")])
        with self.assertRaises(NoMatchingKeyError):
            cell_open(cell, passphrases=["wrong"])

    def test_no_key_material_at_all(self):
        with self.assertRaises(NoMatchingKeyError):
            cell_open(self.seal())

    def test_passphrase_is_not_unicode_normalized(self):
        # WebCrypto feeds PBKDF2 the raw UTF-8 bytes with no normalization, so
        # composed and decomposed forms are different passphrases everywhere.
        # Spelled out via unicodedata rather than source literals, because an
        # editor that normalizes this file would otherwise silently void the test.
        import unicodedata

        composed = unicodedata.normalize("NFC", "cafe\u0301")
        decomposed = unicodedata.normalize("NFD", composed)
        self.assertNotEqual(composed, decomposed)
        cell = self.seal(recipients=[Recipient.passphrase_(composed)])
        with self.assertRaises(NoMatchingKeyError):
            cell_open(cell, passphrases=[decomposed])

    def test_quorum_requires_the_threshold(self):
        keys = [KeyRecord.generate(f"K{i}") for i in range(3)]
        cell = self.seal(recipients=[Recipient.for_key(k) for k in keys], threshold=2)
        self.assertEqual(cell["header"]["threshold"], {"required": 2, "of_total": 3})
        self.assertEqual(cell_open(cell, keys=keys[:2]).data, b"payload")
        self.assertEqual(cell_open(cell, keys=keys[1:]).data, b"payload")
        with self.assertRaises(QuorumNotMetError):
            cell_open(cell, keys=keys[:1])

    def test_threshold_is_clamped_to_the_recipient_count(self):
        cell = self.seal(threshold=5)
        self.assertEqual(cell["header"]["threshold"], {"required": 1, "of_total": 1})

    def test_share_index_is_omitted_on_non_quorum_cells(self):
        # §6.4: omitted, not null — the two forms hash differently.
        entry = self.seal()["header"]["access_map"][0]
        self.assertNotIn("share_index", entry)

    def test_share_index_is_the_x_coordinate_on_quorum_cells(self):
        keys = [KeyRecord.generate(f"K{i}") for i in range(3)]
        cell = self.seal(recipients=[Recipient.for_key(k) for k in keys], threshold=2)
        self.assertEqual([e["share_index"] for e in cell["header"]["access_map"]], [1, 2, 3])


class TestLifetimeGates(CellTestCase):
    def test_expired_retention_is_refused_by_conforming_software(self):
        past = int(time.time()) - DAY
        cell = self.seal(lifetime={"type": "record", "advisory": {"retain_until": past}})
        with self.assertRaises(LifetimeError):
            cell_open(cell, keys=[self.alice])

    def test_advisory_gates_are_advisory(self):
        # §8.1 is explicit that a keyholder can disregard these, and this
        # library is the independent opener the spec describes. Making that
        # bypass an honest parameter is better than pretending it does not exist.
        past = int(time.time()) - DAY
        cell = self.seal(lifetime={"type": "record", "advisory": {"retain_until": past}})
        self.assertEqual(
            cell_open(cell, keys=[self.alice], enforce_advisory=False).data, b"payload"
        )

    def test_timed_release_locks_until_its_date(self):
        future = int(time.time()) + DAY
        cell = self.seal(
            lifetime={"type": "timed_release", "advisory": {"release_at": future}}
        )
        with self.assertRaises(LifetimeError):
            cell_open(cell, keys=[self.alice])
        self.assertEqual(cell_open(cell, keys=[self.alice], now=future + 1).data, b"payload")

    def test_disposal_never_blocks_an_open(self):
        # §8.2: a passed disposal date says something about the operator's
        # retention schedule, not about the recipient's permission.
        past = int(time.time()) - DAY
        cell = self.seal(
            lifetime={"type": "record", "advisory": {"retain_until": None},
                      "disposal": {"at": past, "action": "delete"}}
        )
        self.assertEqual(cell_open(cell, keys=[self.alice]).data, b"payload")

    def test_flat_legacy_lifetime_is_read_under_its_own_rules(self):
        cell = self.seal(lifetime={"type": "session", "expires_at": None, "on_expiry": "delete"})
        result = cell_open(cell, keys=[self.alice])
        self.assertEqual(result.lifetime.type, "session")
        self.assertEqual(result.lifetime.disposal_action, "delete")


class TestEncodingAndMalformed(CellTestCase):
    def test_encoder_emits_standard_base64_only(self):
        # §4.0: base64url is not merely non-canonical, it is unparseable by the
        # reference (atob throws on - and _).
        blob = json.dumps(self.seal(bytes(range(256)) * 8, sender=self.alice))
        for field in ("ciphertext", "iv", "header_hash", "header_sig"):
            self.assertIn(field, blob)
        b64_values = _collect_b64(json.loads(blob))
        self.assertTrue(b64_values)
        for value in b64_values:
            self.assertNotIn("-", value)
            self.assertNotIn("_", value)

    def test_decoder_tolerates_base64url_input(self):
        # §4.0 says decoders SHOULD accept it for robustness. Tolerating it on
        # input costs nothing; emitting it breaks every other reader.
        self.assertEqual(b64decode("-_8="), b64decode("+/8="))

    def test_invalid_base64_is_a_clean_error(self):
        cell = self.seal()
        cell["payload"]["ciphertext"] = "not base64!!"
        with self.assertRaises(MalformedCellError):
            cell_open(cell, keys=[self.alice])

    def test_missing_header_is_a_clean_error(self):
        cell = self.seal()
        del cell["header"]
        with self.assertRaises(MalformedCellError):
            cell_open(cell, keys=[self.alice])

    def test_gzip_bomb_is_refused(self):
        bomb = crypto.gzip_compress(b"\0" * (4 << 20))
        with self.assertRaises(MalformedCellError):
            crypto.gzip_decompress(bomb, max_bytes=1 << 20)

    def test_manifest_length_past_the_end_is_refused(self):
        cell = self.seal()
        # Re-seal by hand with a corrupt manifest length so the GCM tag still
        # verifies and only the §5 framing is wrong.
        cek = crypto.ecdh_unwrap_cek(
            cell["header"]["access_map"][0]["wrapped_cek"], self.alice.private
        )
        plain = crypto.gzip_compress(b"\xff\xff\xff\xff" + b"{}")
        from cellular_defense.cell import cell_aad

        iv, ct = crypto.aes_gcm_encrypt(
            cek, plain, cell_aad(cell["header"], cell["version"])
        )
        cell["payload"]["iv"] = b64encode(iv)
        cell["payload"]["ciphertext"] = b64encode(ct)
        cell["header"]["payload_hash"] = b64encode(crypto.sha256(ct))
        rehash(cell)
        with self.assertRaises(MalformedCellError):
            cell_open(cell, keys=[self.alice])


class TestLegacyFormats(CellTestCase):
    def test_legacy_v2_cell_without_hkdf_opens(self):
        # §12: pre-spec cells used the raw ECDH output as the AES-KW key, had no
        # header at all, and carried plaintext filename metadata. New writers
        # must never produce this; readers still have to handle it.
        from cryptography.hazmat.primitives import keywrap
        from cryptography.hazmat.primitives.asymmetric import ec

        cek = bytes(range(32))
        ephemeral = ec.generate_private_key(crypto.CURVE)
        shared = ephemeral.exchange(ec.ECDH(), self.alice.public)
        body = crypto.gzip_compress(b"legacy content")
        iv, ct = crypto.aes_gcm_encrypt(cek, body, None)
        legacy = {
            "cd_version": "2.0",
            "doc_id": "legacy-1",
            "original_filename": "old.txt",
            "content_type": "text/plain",
            "recipients": [
                {
                    "method": "ecdh-p256",
                    "label": "Alice",
                    "fingerprint": self.alice.fingerprint,
                    "wrapped_cek": {
                        "eph_spki": b64encode(crypto.export_spki(ephemeral.public_key())),
                        "ct": b64encode(keywrap.aes_key_wrap(shared[:32], cek)),
                    },
                }
            ],
            "encrypted_body": {"iv": b64encode(iv), "ciphertext": b64encode(ct)},
        }
        result = cell_open(legacy, keys=[self.alice])
        self.assertEqual(result.data, b"legacy content")
        self.assertEqual(result.filename, "old.txt")


class TestSerializationRouting(CellTestCase):
    def test_canonical_versions_are_held_as_a_set(self):
        # §12 warns that an inline `version == "1.2"` test elsewhere silently
        # downgrades a new version's serialization with no error anywhere.
        from cellular_defense import AAD_VERSIONS, CANONICAL_VERSIONS, SUPPORTED_VERSIONS

        self.assertEqual(CANONICAL_VERSIONS, {"1.2", "1.3"})
        self.assertEqual(AAD_VERSIONS, {"1.1", "1.2", "1.3"})
        self.assertIn(CELL_FORMAT_VERSION, CANONICAL_VERSIONS)
        self.assertIn(CELL_FORMAT_VERSION, AAD_VERSIONS)
        self.assertTrue(CANONICAL_VERSIONS <= SUPPORTED_VERSIONS)
        self.assertTrue(AAD_VERSIONS <= SUPPORTED_VERSIONS)

    def test_legacy_versions_use_json_stringify_serialization(self):
        header = {"b": 1, "a": 2}
        self.assertEqual(serialize_header(header, "1.0"), js_stringify(header).encode())
        self.assertEqual(serialize_header(header, "1.3"), canonical_bytes(header))
        self.assertNotEqual(serialize_header(header, "1.0"), serialize_header(header, "1.3"))


class TestKeyFiles(CellTestCase):
    def test_cdpub_round_trip(self):
        doc = self.alice.to_cdpub()
        self.assertEqual(doc["cd_pubkey"], "2.0")
        self.assertEqual(KeyRecord.from_cdpub(doc).fingerprint, self.alice.fingerprint)

    def test_cdpub_with_a_lying_fingerprint_is_refused(self):
        doc = self.alice.to_cdpub()
        doc["fingerprint"] = self.bob.fingerprint
        with self.assertRaises(MalformedCellError):
            KeyRecord.from_cdpub(doc)

    def test_cdkey_round_trip(self):
        restored = KeyRecord.from_cdkey(self.alice.to_cdkey())
        self.assertEqual(restored.fingerprint, self.alice.fingerprint)
        cell = self.seal()
        self.assertEqual(cell_open(cell, keys=[restored]).data, b"payload")

    def test_fingerprint_is_sha256_spki_truncated(self):
        expected = crypto.sha256(b64decode(self.alice.spki)).hex()[:16]
        self.assertEqual(self.alice.fingerprint, expected)
        self.assertEqual(len(self.alice.fingerprint), 16)


def _mutate(cell: dict, fn) -> dict:
    clone = copy.deepcopy(cell)
    fn(clone)
    return clone


def _collect_b64(value, out=None) -> list[str]:
    """Every string in the cell that looks like an encoded binary field."""
    out = [] if out is None else out
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"filename", "content_type", "label", "method", "type", "doc_id"}:
                continue
            _collect_b64(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect_b64(item, out)
    elif isinstance(value, str) and len(value) > 16:
        out.append(value)
    return out


if __name__ == "__main__":
    unittest.main()
