// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Runs the shared conformance vectors in {@code conformance/vectors}.
 *
 * <p>This is the test a new language port writes first. It reads a
 * language-neutral manifest and asserts two things per vector: the cells that
 * must open produce the exact expected plaintext, filename, media type and
 * sender meta; and the cells that must be refused are refused.
 *
 * <p>The refusals carry most of the weight. An implementation that opens every
 * positive vector and also opens {@code reject-tampered-aad} is not a partial
 * pass — it has no metadata authentication at all.
 */
class ConformanceTest {

    private static Path vectorsDir() {
        return Path.of(System.getProperty("user.dir"), "..", "..", "conformance", "vectors")
                .normalize();
    }

    private static Map<String, Object> loadJson(Path path) throws Exception {
        return Json.asObject(Json.parse(Files.readAllBytes(path)));
    }

    private static KeyRecord loadKey(Path dir, String name) throws Exception {
        return KeyRecord.fromCdkey(loadJson(dir.resolve("../keys/" + name + ".cdkey").normalize()));
    }

    private static Cell.OpenOptions optionsFor(Path dir, Map<String, Object> spec)
            throws Exception {
        Cell.OpenOptions opts = new Cell.OpenOptions();
        List<Object> keys = Json.array(spec, "keys");
        if (keys != null) {
            for (Object name : keys) {
                opts.keys.add(loadKey(dir, (String) name));
            }
        }
        List<Object> passphrases = Json.array(spec, "passphrases");
        if (passphrases != null) {
            for (Object passphrase : passphrases) {
                opts.passphrases.add((String) passphrase);
            }
        }
        return opts;
    }

    /**
     * Map the manifest's portable reason codes onto this library's exception
     * types. A port in another language substitutes its own; the reason codes
     * are the portable part, and the manifest is explicit that the refusal is
     * normative while the specific reason code is not.
     */
    private static Class<? extends CellException> expectedType(String reason) {
        return switch (reason) {
            case "header-hash-missing", "header-hash-mismatch", "payload-hash-mismatch" ->
                    CellException.Integrity.class;
            case "signature-invalid" -> CellException.Signature.class;
            case "signature-der-encoded" -> CellException.Malformed.class;
            case "aad-mismatch" -> CellException.Decryption.class;
            case "unsupported-version" -> CellException.UnsupportedVersion.class;
            case "quorum-not-met" -> CellException.QuorumNotMet.class;
            case "no-matching-key" -> CellException.NoMatchingKey.class;
            case "retention-expired", "timed-release-locked" -> CellException.Lifetime.class;
            default -> throw new IllegalArgumentException("unknown reject_reason " + reason);
        };
    }

    @Test
    void conformanceVectors() throws Exception {
        Path dir = vectorsDir();
        Assumptions.assumeTrue(Files.exists(dir.resolve("manifest.json")),
                "conformance vectors not present");
        Map<String, Object> manifest = loadJson(dir.resolve("manifest.json"));
        List<Object> vectors = Json.array(manifest, "vectors");

        List<String> failures = new ArrayList<>();
        int opened = 0;
        int refused = 0;

        for (Object vectorValue : vectors) {
            Map<String, Object> vector = Json.asObject(vectorValue);
            String id = Json.string(vector, "id");
            Map<String, Object> cell = loadJson(dir.resolve(Json.string(vector, "file")));
            Map<String, Object> openWith = Json.object(vector, "open_with");
            Cell.OpenOptions opts = optionsFor(dir, openWith);

            if ("open".equals(Json.string(vector, "expect"))) {
                try {
                    Cell.OpenResult result = Cell.open(cell, opts);
                    opened++;

                    Map<String, Object> expected = Json.object(vector, "plaintext");
                    byte[] payload = Files.readAllBytes(dir.resolve(Json.string(expected, "file")));
                    if (!java.util.Arrays.equals(result.data(), payload)) {
                        failures.add(id + ": plaintext differs from the committed payload file");
                    }
                    if (result.data().length != Json.integer(expected, "size", -1)) {
                        failures.add(id + ": plaintext size differs");
                    }
                    if (!hex(CellCrypto.sha256(result.data())).equals(Json.string(expected, "sha256"))) {
                        failures.add(id + ": plaintext sha256 differs");
                    }
                    if (!result.filename().equals(Json.string(vector, "filename"))) {
                        failures.add(id + ": filename = " + result.filename());
                    }
                    if (!result.contentType().equals(Json.string(vector, "content_type"))) {
                        failures.add(id + ": content_type = " + result.contentType());
                    }
                    if (vector.containsKey("meta")) {
                        String got = result.meta() == null ? null
                                : Canonical.canonicalize(result.meta());
                        String want = Canonical.canonicalize(vector.get("meta"));
                        if (!want.equals(got)) {
                            failures.add(id + ": meta = " + got + ", want " + want);
                        }
                    }
                    String signer = Json.string(vector, "signer");
                    if (signer != null) {
                        String want = loadKey(dir, signer).fingerprint();
                        if (!result.signed() || !want.equals(result.signerFingerprint())) {
                            failures.add(id + ": signer = " + result.signerFingerprint());
                        }
                    }
                    List<Object> alternatives = Json.array(openWith, "also_opens_with");
                    if (alternatives != null) {
                        for (int i = 0; i < alternatives.size(); i++) {
                            Map<String, Object> alt = Json.asObject(alternatives.get(i));
                            try {
                                Cell.OpenResult other = Cell.open(cell, optionsFor(dir, alt));
                                if (!java.util.Arrays.equals(other.data(), result.data())) {
                                    failures.add(id + ": also_opens_with[" + i
                                            + "] gave different plaintext");
                                }
                            } catch (CellException e) {
                                failures.add(id + ": also_opens_with[" + i + "] failed: "
                                        + e.getMessage());
                            }
                        }
                    }
                } catch (CellException e) {
                    failures.add(id + ": should have opened: " + e.getMessage());
                }
            } else {
                String reason = Json.string(vector, "reject_reason");
                try {
                    Cell.open(cell, opts);
                    failures.add(id + ": opened but must be refused (" + reason + ")");
                } catch (CellException e) {
                    refused++;
                    Class<? extends CellException> want = expectedType(reason);
                    if (!want.isInstance(e)) {
                        failures.add(id + ": refused with " + e.getClass().getSimpleName()
                                + ", expected " + want.getSimpleName());
                    }
                }
            }

            Map<String, Object> mustNot = Json.object(vector, "must_not_open_with");
            if (mustNot != null) {
                try {
                    Cell.open(cell, optionsFor(dir, mustNot));
                    failures.add(id + ": opened with key material that must not open it");
                } catch (CellException expectedFailure) {
                    // correct
                }
            }
        }

        if (!failures.isEmpty()) {
            fail(failures.size() + " failures:\n" + String.join("\n", failures));
        }
        assertTrue(opened > 0 && refused > 0, "manifest produced no vectors");
        System.out.println("conformance: " + opened + " opened, " + refused + " refused");
    }

    @Test
    void everySupportedVersionHasAVector() throws Exception {
        Path dir = vectorsDir();
        Assumptions.assumeTrue(Files.exists(dir.resolve("manifest.json")));
        Map<String, Object> manifest = loadJson(dir.resolve("manifest.json"));
        List<String> covered = new ArrayList<>();
        for (Object vector : Json.array(manifest, "vectors")) {
            covered.add(Json.string(Json.asObject(vector), "cell_version"));
        }
        // §12 requires 1.0-1.3 plus legacy v2.x to stay readable. A version with
        // no vector is a version nobody actually tests.
        for (String version : List.of("1.0", "1.1", "1.2", "1.3", "2.0")) {
            assertTrue(covered.contains(version), "no vector covers version " + version);
        }
    }

    /**
     * Documents §8.1 rather than merely testing it: the advisory half of
     * lifetime is not enforced against a keyholder, and an opener written from
     * the spec can disregard it. The vector still requires refusal by DEFAULT —
     * that is the conformance claim — but an explicit override is not a
     * violation.
     */
    @Test
    void advisoryGatesAreAdvisory() throws Exception {
        Path dir = vectorsDir();
        Assumptions.assumeTrue(Files.exists(dir.resolve("manifest.json")));
        Map<String, Object> manifest = loadJson(dir.resolve("manifest.json"));
        for (Object vectorValue : Json.array(manifest, "vectors")) {
            Map<String, Object> vector = Json.asObject(vectorValue);
            if (!"retention-expired".equals(Json.string(vector, "reject_reason"))) {
                continue;
            }
            Map<String, Object> cell = loadJson(dir.resolve(Json.string(vector, "file")));
            Cell.OpenOptions opts = optionsFor(dir, Json.object(vector, "open_with"));
            opts.ignoreAdvisory = true;
            assertTrue(Cell.open(cell, opts).data().length > 0);
        }
    }

    /**
     * PBKDF2 must agree with the other implementations byte for byte.
     *
     * <p>{@link javax.crypto.spec.PBEKeySpec} takes a {@code char[]}, and the
     * specification says nothing about how a provider turns that into the byte
     * string PKCS#5 wants. This pins SunJCE's answer against a value computed by
     * the Python port, including a non-ASCII passphrase where the encoding
     * choice actually shows.
     */
    @Test
    void pbkdf2MatchesTheOtherImplementations() {
        byte[] salt = "conformance-salt".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // ASCII: any plausible encoding agrees, so this only pins the algorithm.
        assertEquals("6eed6be08353f84e941fdac423810974384df44d687563c0b9e896744f17e2d3",
                hex(CellCrypto.derivePassphraseKey("conformance-test-passphrase", salt, 1000)));

        // Non-ASCII is the case that actually distinguishes the encodings, and
        // the JDK does not specify one: PBEKeySpec takes a char[] and the
        // provider decides what byte string PKCS#5 receives. SunJCE uses UTF-8
        // for the HMAC-SHA2 variants, which is what makes this interoperate —
        // but that is an observation about the provider, not a guarantee from
        // the specification, so it is pinned here rather than assumed.
        //
        // Expected value computed independently by the Python port:
        //   hashlib.pbkdf2_hmac("sha256", "caf\u00e9".encode("utf-8"),
        //                       b"conformance-salt", 1000, 32)
        //
        // The passphrase is written as an escape so that re-encoding this file,
        // or an editor normalising NFC to NFD, cannot silently void the test.
        assertEquals("eb8382ed55594949a9c948993cd040ac1cfce085fa44e0c3affc86a4eb713e19",
                hex(CellCrypto.derivePassphraseKey("caf\u00e9", salt, 1000)),
                "SunJCE's char[] encoding disagrees with the other implementations");
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }
}
