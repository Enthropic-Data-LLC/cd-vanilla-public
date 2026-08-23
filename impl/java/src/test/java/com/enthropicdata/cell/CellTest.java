// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Sealing and opening, with the negative cases carrying most of the weight.
 *
 * <p>Round-trips prove only that the library agrees with itself. What matters is
 * that the <em>refusals</em> happen.
 */
class CellTest {

    private static final long DAY = 86400;
    private static final KeyRecord ALICE = KeyRecord.generate("Alice");
    private static final KeyRecord BOB = KeyRecord.generate("Bob");

    private static Map<String, Object> seal(byte[] data, List<Cell.Recipient> recipients,
            Cell.CreateOptions opts) {
        return Cell.create(data, "f.txt", recipients, opts);
    }

    private static Map<String, Object> sealToAlice() {
        return seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), null);
    }

    private static Cell.OpenOptions keys(KeyRecord... records) {
        Cell.OpenOptions opts = new Cell.OpenOptions();
        opts.keys = List.of(records);
        return opts;
    }

    /**
     * Recompute {@code header_hash} — what any attacker editing a header does
     * first, since the hash is unkeyed. Every "attacker edits the header" test
     * needs it, and that is precisely why the AAD binding and the signature
     * exist.
     */
    private static void rehash(Map<String, Object> cell) {
        byte[] bytes = Cell.serializeHeader(Json.object(cell, "header"),
                Json.string(cell, "version"));
        cell.put("header_hash", CellCrypto.encodeB64(CellCrypto.sha256(bytes)));
    }

    @Test
    void roundTrip() {
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.contentType = "text/plain";
        Map<String, Object> cell = seal("hello".getBytes(),
                List.of(Cell.Recipient.forKey(ALICE)), opts);
        Cell.OpenResult result = Cell.open(cell, keys(ALICE));
        assertArrayEquals("hello".getBytes(), result.data());
        assertEquals("text/plain", result.contentType());
        assertFalse(result.signed());
    }

    @Test
    void payloadEdgeCases() {
        for (int size : new int[] {0, 1, 4096}) {
            byte[] data = new byte[size];
            for (int i = 0; i < size; i++) {
                data[i] = (byte) i;
            }
            Map<String, Object> cell = seal(data, List.of(Cell.Recipient.forKey(ALICE)), null);
            assertArrayEquals(data, Cell.open(cell, keys(ALICE)).data(), "size " + size);
        }
    }

    @Test
    void metadataIsNotVisibleInTheCell() {
        // §5: the manifest lives inside the ciphertext. If the filename appears
        // anywhere in the serialized cell, metadata confidentiality is broken.
        Map<String, Object> cell = Cell.create(new byte[1000], "secret-merger-terms.pdf",
                List.of(Cell.Recipient.forKey(ALICE)), null);
        assertFalse(Json.writePretty(cell).contains("secret-merger-terms"),
                "filename leaked into the cell");
    }

    @Test
    void reformattingDoesNotBreakVerification() {
        // The point of canonicalization (§4.1.1): a cell pretty-printed or
        // key-reordered in transit still verifies.
        Map<String, Object> cell = sealToAlice();
        Map<String, Object> reparsed = Json.asObject(Json.parse(Json.writePretty(cell)));
        assertNotNull(Cell.verify(reparsed, null));
        assertArrayEquals("x".getBytes(), Cell.open(reparsed, keys(ALICE)).data());
    }

    @Test
    void missingHeaderHashIsARejection() {
        // §4.1: absence must not be licence to skip the checks — deleting one
        // field would otherwise disable header, ciphertext and signature
        // verification together.
        Map<String, Object> cell = sealToAlice();
        cell.remove("header_hash");
        assertThrows(CellException.Integrity.class, () -> Cell.open(cell, keys(ALICE)));
    }

    @Test
    void editedHeaderWithoutRehashIsRefused() {
        Map<String, Object> cell = sealToAlice();
        Json.object(Json.object(cell, "header"), "policy").put("copy_protection", "none");
        assertThrows(CellException.Integrity.class, () -> Cell.open(cell, keys(ALICE)));
    }

    @Test
    void tamperedCiphertextFailsPayloadHash() {
        Map<String, Object> cell = sealToAlice();
        Map<String, Object> payload = Json.object(cell, "payload");
        byte[] ct = CellCrypto.decodeB64(Json.string(payload, "ciphertext"), "ct");
        ct[0] ^= 1;
        payload.put("ciphertext", CellCrypto.encodeB64(ct));
        assertThrows(CellException.Integrity.class, () -> Cell.open(cell, keys(ALICE)));
    }

    @Test
    void tamperedAadFailsTheGcmTag() {
        // The attacker edits AAD-bound metadata AND recomputes the unkeyed
        // header_hash, so §10 steps 1-3 all pass. The AAD binding is the only
        // thing left, and it must catch this.
        Map<String, Object> cell = sealToAlice();
        Json.object(Json.object(cell, "header"), "policy").put("copy_protection", "none");
        rehash(cell);
        assertThrows(CellException.Decryption.class, () -> Cell.open(cell, keys(ALICE)));
    }

    @Test
    void versionDowngradeFailsTheGcmTag() {
        // §4.4: rewriting version to 1.0 would strip the AAD from the decrypt.
        // The ciphertext was produced WITH AAD, so the tag fails; an attacker
        // cannot re-encrypt without the CEK.
        Map<String, Object> cell = sealToAlice();
        cell.put("version", "1.0");
        rehash(cell);
        assertThrows(CellException.Decryption.class, () -> Cell.open(cell, keys(ALICE)));
    }

    @Test
    void unknownVersionIsRefused() {
        Map<String, Object> cell = sealToAlice();
        cell.put("version", "9.9");
        assertThrows(CellException.UnsupportedVersion.class, () -> Cell.open(cell, keys(ALICE)));
    }

    @Test
    void forgedAccessMapIsCaughtByTheSignature() {
        // access_map is not in the AAD (it does not exist at encryption time),
        // so header_hash covers it — and an attacker who recomputes that unkeyed
        // hash is caught by the signature.
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.sender = ALICE;
        Map<String, Object> cell = seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), opts);
        Map<String, Object> other = seal("x".getBytes(), List.of(Cell.Recipient.forKey(BOB)), null);
        Json.object(cell, "header").put("access_map",
                Json.array(Json.object(other, "header"), "access_map"));
        rehash(cell);
        assertThrows(CellException.Signature.class, () -> Cell.open(cell, keys(BOB)));
    }

    @Test
    void signatureReportsTheRealFingerprint() {
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.sender = BOB;
        Map<String, Object> cell = seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), opts);
        Cell.OpenResult result = Cell.open(cell, keys(ALICE));
        assertTrue(result.signed());
        assertEquals(BOB.fingerprint(), result.signerFingerprint());
    }

    @Test
    void headerSigByIsNotTrusted() {
        // §4.1: a self-asserted label. Changing it must not change attribution.
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.sender = BOB;
        Map<String, Object> cell = seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), opts);
        cell.put("header_sig_by", "Trust Me Inc");
        rehash(cell);
        Cell.OpenResult result = Cell.open(cell, keys(ALICE));
        assertEquals(BOB.fingerprint(), result.signerFingerprint());
        assertEquals("Trust Me Inc", result.claimedSigner());
    }

    @Test
    void derEncodedSignatureIsRefused() {
        // §4.1's named trap. Java makes this easy to avoid — it has had a P1363
        // signature format since JDK 11 — but a cell arriving from a
        // DER-defaulting implementation must still be refused.
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.sender = BOB;
        Map<String, Object> cell = seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), opts);
        byte[] raw = CellCrypto.decodeB64(Json.string(cell, "header_sig"), "sig");
        byte[] der = new byte[70];
        der[0] = 0x30;
        der[1] = 0x44;
        der[2] = 0x02;
        der[3] = 0x20;
        System.arraycopy(raw, 0, der, 4, 32);
        der[36] = 0x02;
        der[37] = 0x20;
        System.arraycopy(raw, 32, der, 38, 32);
        cell.put("header_sig", CellCrypto.encodeB64(der));
        assertThrows(CellException.Malformed.class, () -> Cell.open(cell, keys(ALICE)));
    }

    @Test
    void strippedSignatureIsUndetectableButExpectedSignerCatchesIt() {
        // §4.1: an attacker can delete the signature and the result is
        // byte-indistinguishable from a cell that was never signed. "Opened
        // without error" is not evidence of authorship.
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.sender = BOB;
        Map<String, Object> cell = seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), opts);
        cell.put("header_sig", null);
        cell.put("header_sig_by", null);
        cell.put("header_sig_key", null);
        rehash(cell);
        assertFalse(Cell.open(cell, keys(ALICE)).signed());

        Cell.OpenOptions strict = keys(ALICE);
        strict.expectedSigner = BOB.fingerprint();
        assertThrows(CellException.Signature.class, () -> Cell.open(cell, strict));
    }

    @Test
    void wrongKeyIsRefused() {
        assertThrows(CellException.NoMatchingKey.class, () -> Cell.open(sealToAlice(), keys(BOB)));
    }

    @Test
    void shareIndexIsOmittedOnNonQuorumCells() {
        // §6.4: omitted, not null — the two forms hash differently.
        Map<String, Object> entry = Json.asObject(
                Json.array(Json.object(sealToAlice(), "header"), "access_map").get(0));
        assertFalse(entry.containsKey("share_index"));
    }

    @Test
    void quorumRequiresTheThreshold() {
        KeyRecord k1 = KeyRecord.generate("K1");
        KeyRecord k2 = KeyRecord.generate("K2");
        KeyRecord k3 = KeyRecord.generate("K3");
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.threshold = 2;
        Map<String, Object> cell = seal("quorum".getBytes(), List.of(
                Cell.Recipient.forKey(k1), Cell.Recipient.forKey(k2), Cell.Recipient.forKey(k3)),
                opts);
        assertArrayEquals("quorum".getBytes(), Cell.open(cell, keys(k1, k2)).data());
        assertThrows(CellException.QuorumNotMet.class, () -> Cell.open(cell, keys(k1)));

        List<Object> entries = Json.array(Json.object(cell, "header"), "access_map");
        for (int i = 0; i < entries.size(); i++) {
            assertEquals(i + 1, Json.integer(Json.asObject(entries.get(i)), "share_index", -1));
        }
    }

    @Test
    void passphraseEntries() {
        Map<String, Object> cell = seal("x".getBytes(),
                List.of(Cell.Recipient.passphrase("right", null)), null);
        Cell.OpenOptions right = new Cell.OpenOptions();
        right.passphrases = List.of("right");
        assertArrayEquals("x".getBytes(), Cell.open(cell, right).data());

        Cell.OpenOptions wrong = new Cell.OpenOptions();
        wrong.passphrases = List.of("wrong");
        assertThrows(CellException.NoMatchingKey.class, () -> Cell.open(cell, wrong));
    }

    @Test
    void lifetimeGates() {
        long now = KeyRecord.now();

        Cell.CreateOptions expiredOpts = new Cell.CreateOptions();
        expiredOpts.lifetime = Json.of("type", "record",
                "advisory", Json.of("retain_until", (double) (now - DAY)));
        Map<String, Object> expired =
                seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), expiredOpts);
        assertThrows(CellException.Lifetime.class, () -> Cell.open(expired, keys(ALICE)));

        // §8.1 is explicit that a keyholder can disregard this, and this library
        // is the independent opener the spec describes. Making the bypass an
        // honest option beats pretending it does not exist.
        Cell.OpenOptions bypass = keys(ALICE);
        bypass.ignoreAdvisory = true;
        assertArrayEquals("x".getBytes(), Cell.open(expired, bypass).data());

        Cell.CreateOptions lockedOpts = new Cell.CreateOptions();
        lockedOpts.lifetime = Json.of("type", "timed_release",
                "advisory", Json.of("release_at", (double) (now + DAY)));
        Map<String, Object> locked =
                seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), lockedOpts);
        assertThrows(CellException.Lifetime.class, () -> Cell.open(locked, keys(ALICE)));
        Cell.OpenOptions later = keys(ALICE);
        later.now = now + DAY + 1;
        assertArrayEquals("x".getBytes(), Cell.open(locked, later).data());

        // §8.2: a passed disposal date describes the operator's retention
        // schedule, not the recipient's permission. It must never block an open.
        Cell.CreateOptions disposedOpts = new Cell.CreateOptions();
        disposedOpts.lifetime = Json.of("type", "record",
                "disposal", Json.of("at", (double) (now - DAY), "action", "delete"));
        Map<String, Object> disposed =
                seal("x".getBytes(), List.of(Cell.Recipient.forKey(ALICE)), disposedOpts);
        assertArrayEquals("x".getBytes(), Cell.open(disposed, keys(ALICE)).data());
    }

    @Test
    void keyFiles() {
        assertEquals(ALICE.fingerprint(), KeyRecord.fromCdpub(ALICE.toCdpub()).fingerprint());
        assertEquals(ALICE.fingerprint(), KeyRecord.fromCdkey(ALICE.toCdkey()).fingerprint());

        // A lying fingerprint must be refused: the value is derived, not
        // authoritative, and trusting it lets an attacker point a known-good
        // label at a key they control.
        Map<String, Object> doc = ALICE.toCdpub();
        doc.put("fingerprint", "0000000000000000");
        assertThrows(CellException.Malformed.class, () -> KeyRecord.fromCdpub(doc));
    }

    @Test
    void encoderEmitsStandardBase64Only() {
        // §4.0: base64url is not merely non-canonical, it is unparseable by the
        // reference — atob() throws on '-' and '_'.
        byte[] data = new byte[512];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.sender = ALICE;
        Map<String, Object> cell = seal(data, List.of(Cell.Recipient.forKey(ALICE)), opts);
        Map<String, Object> payload = Json.object(cell, "payload");
        for (String field : List.of(Json.string(payload, "ciphertext"), Json.string(payload, "iv"),
                Json.string(cell, "header_hash"), Json.string(cell, "header_sig"))) {
            assertFalse(field.contains("-") || field.contains("_"),
                    "base64url characters in " + field);
        }
        // Decoders SHOULD accept base64url on input; emitting it breaks readers.
        assertArrayEquals(CellCrypto.decodeB64("+/8=", "t"), CellCrypto.decodeB64("-_8=", "t"));
    }

    @Test
    void ulidIsSortableAndWellFormed() {
        String first = Ulid.generate(1000L, new byte[10]);
        byte[] high = new byte[10];
        java.util.Arrays.fill(high, (byte) 0xFF);
        String second = Ulid.generate(2000L, high);
        assertEquals(26, first.length());
        assertEquals(26, second.length());
        assertTrue(first.compareTo(second) < 0, "ULIDs must sort by creation time");
        assertNull(first.replaceAll("[0123456789ABCDEFGHJKMNPQRSTVWXYZ]", "").isEmpty()
                ? null : "non-Crockford characters in " + first);
    }
}
