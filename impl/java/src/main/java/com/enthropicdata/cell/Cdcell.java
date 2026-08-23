// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * {@code cdcell} — a command-line opener, sealer and verifier for {@code .cell} files.
 *
 * <pre>
 * cdcell keygen  --label Alice --out alice
 * cdcell seal    report.pdf --to alice.cdpub --out report.cell
 * cdcell verify  report.cell
 * cdcell inspect report.cell
 * cdcell open    report.cell --key alice.cdkey --out ./
 * </pre>
 *
 * <p>{@code verify} and {@code inspect} need no key material at all: that a
 * third party can confirm a cell has not been altered, and see exactly what it
 * does and does not leak, without being able to read it, is the property the
 * format rests on.
 */
public final class Cdcell {

    private Cdcell() {}

    public static void main(String[] args) {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        String command = args[0];
        String[] rest = java.util.Arrays.copyOfRange(args, 1, args.length);
        try {
            switch (command) {
                case "keygen" -> keygen(new Args(rest, "label", "out"));
                case "seal" -> seal(new Args(rest, "to", "threshold", "sign", "meta", "out"));
                case "verify" -> verify(new Args(rest, "expect-signer"));
                case "inspect" -> inspect(new Args(rest));
                case "open" -> open(new Args(rest, "key", "expect-signer", "out"));
                case "-h", "--help", "help" -> usage();
                default -> {
                    System.err.println("unknown command \"" + command + "\"\n");
                    usage();
                    System.exit(2);
                }
            }
        } catch (CellException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("error: " + e);
            System.exit(1);
        }
    }

    private static void usage() {
        System.err.print("""
                cdcell — seal, open and verify .cell documents

                  cdcell keygen  --label NAME --out STEM        generate a P-256 keypair
                  cdcell seal    FILE --to PUB [--to PUB]...    encrypt into a .cell
                  cdcell verify  CELL                          check the audit chain (no key needed)
                  cdcell inspect CELL                          show what an observer can see
                  cdcell open    CELL --key KEY --out PATH     decrypt
                """);
    }

    /**
     * A deliberately small parser: flags may appear before or after positionals,
     * because users write the filename first and every other tool lets them.
     */
    private static final class Args {
        private final List<String> positional = new ArrayList<>();
        private final Map<String, List<String>> valued = new HashMap<>();
        private final List<String> switches = new ArrayList<>();

        Args(String[] args, String... takesValue) {
            List<String> valuedNames = List.of(takesValue);
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (!arg.startsWith("--")) {
                    positional.add(arg);
                    continue;
                }
                String name = arg.substring(2);
                String inline = null;
                int equals = name.indexOf('=');
                if (equals >= 0) {
                    inline = name.substring(equals + 1);
                    name = name.substring(0, equals);
                }
                if (valuedNames.contains(name)) {
                    String value = inline;
                    if (value == null) {
                        if (++i >= args.length) {
                            throw new CellException("--" + name + " needs a value");
                        }
                        value = args[i];
                    }
                    valued.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
                } else {
                    switches.add(name);
                }
            }
        }

        String one(String name, String fallback) {
            List<String> values = valued.get(name);
            return values == null || values.isEmpty() ? fallback : values.get(0);
        }

        List<String> many(String name) {
            return valued.getOrDefault(name, List.of());
        }

        boolean has(String name) {
            return switches.contains(name);
        }

        String positional(int index) {
            return index < positional.size() ? positional.get(index) : null;
        }
    }

    // ─── keygen ─────────────────────────────────────────────────────────────

    private static void keygen(Args args) throws Exception {
        String out = args.one("out", null);
        if (out == null) {
            throw new CellException("--out is required");
        }
        KeyRecord key = KeyRecord.generate(args.one("label", "My Key"));
        Path pubPath = Path.of(out + ".cdpub");
        Path keyPath = Path.of(out + ".cdkey");

        Files.writeString(pubPath, Json.writePretty(key.toCdpub()) + "\n");
        Files.writeString(keyPath, Json.writePretty(key.toCdkey()) + "\n");
        try {
            Files.setPosixFilePermissions(keyPath, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Not a POSIX filesystem; nothing to tighten.
        }

        System.out.println("fingerprint  " + key.fingerprint());
        System.out.println("public key   " + pubPath
                + "   (share this — it is how others encrypt to you)");
        System.out.println("private key  " + keyPath
                + "   (never share; there is no recovery)");
    }

    // ─── seal ───────────────────────────────────────────────────────────────

    private static void seal(Args args) throws Exception {
        String source = args.positional(0);
        if (source == null) {
            throw new CellException("usage: cdcell seal FILE --to RECIPIENT.cdpub");
        }
        List<Cell.Recipient> recipients = new ArrayList<>();
        for (String path : args.many("to")) {
            recipients.add(Cell.Recipient.forKey(
                    KeyRecord.fromCdpub(Json.asObject(Json.parse(Files.readAllBytes(Path.of(path)))))));
        }
        if (args.has("passphrase")) {
            String entered = promptPassphrase("Passphrase for this cell: ");
            if (!entered.equals(promptPassphrase("Repeat: "))) {
                throw new CellException("passphrases do not match");
            }
            recipients.add(Cell.Recipient.passphrase(entered, null));
        }
        if (recipients.isEmpty()) {
            throw new CellException("a cell needs at least one recipient (--to or --passphrase)");
        }

        Cell.CreateOptions opts = new Cell.CreateOptions();
        opts.contentType = contentTypeFor(source);
        opts.threshold = Integer.parseInt(args.one("threshold", "1"));
        String meta = args.one("meta", null);
        if (meta != null) {
            opts.meta = Json.parse(meta);
        }
        String sign = args.one("sign", null);
        if (sign != null) {
            opts.sender = KeyRecord.fromCdkey(
                    Json.asObject(Json.parse(Files.readAllBytes(Path.of(sign)))));
        }

        byte[] data = Files.readAllBytes(Path.of(source));
        Map<String, Object> cell = Cell.create(data,
                Path.of(source).getFileName().toString(), recipients, opts);

        Path destination = Path.of(args.one("out", source + ".cell"));
        writeCell(destination, cell);

        Map<String, Object> header = Json.object(cell, "header");
        Map<String, Object> threshold = Json.object(header, "threshold");
        int count = Json.array(header, "access_map").size();
        System.out.println("sealed " + destination + "  (" + count + " recipient"
                + (count == 1 ? "" : "s") + ", " + Json.integer(threshold, "required", 1)
                + "-of-" + Json.integer(threshold, "of_total", 1) + ")");
    }

    // ─── verify ─────────────────────────────────────────────────────────────

    private static void verify(Args args) throws Exception {
        String path = args.positional(0);
        if (path == null) {
            throw new CellException("usage: cdcell verify CELL");
        }
        Cell.VerifyResult result = Cell.verify(readCell(Path.of(path)),
                args.one("expect-signer", null));
        System.out.println("version        " + result.version());
        System.out.println("header_hash    ok");
        System.out.println("payload_hash   " + (result.payloadHashOk() ? "ok" : "absent"));
        if (result.signed()) {
            System.out.println("signature      valid, by key " + result.signerFingerprint());
            System.out.println("               (claims to be \"" + result.claimedSigner()
                    + "\" — self-asserted, check the fingerprint");
            System.out.println("               against a contact you already trust)");
        } else {
            System.out.println("signature      none present");
            System.out.println(
                    "               a signature can be stripped undetectably; absence proves nothing");
        }
    }

    // ─── inspect ────────────────────────────────────────────────────────────

    private static void inspect(Args args) throws Exception {
        String path = args.positional(0);
        if (path == null) {
            throw new CellException("usage: cdcell inspect CELL");
        }
        Map<String, Object> cell = readCell(Path.of(path));
        Map<String, Object> header = Json.object(cell, "header");

        String version = Json.string(cell, "version");
        if (version == null) {
            version = Json.string(cell, "cd_version");
        }
        System.out.println("version      " + version);
        System.out.println("doc_id       " + Json.string(cell, "doc_id"));
        System.out.println("created_at   " + Json.integer(cell, "created_at", 0));
        Map<String, Object> threshold = Json.object(header, "threshold");
        System.out.println("threshold    " + Json.integer(threshold, "required", 1)
                + "-of-" + Json.integer(threshold, "of_total", 1));

        Lifetime lifetime = Lifetime.read(Json.object(header, "lifetime"));
        if (lifetime != null) {
            System.out.println("lifetime     type=" + lifetime.type());
            System.out.println("  advisory   retain_until=" + lifetime.retainUntil()
                    + " release_at=" + lifetime.releaseAt()
                    + " single_use=" + lifetime.singleUse()
                    + " minimum_atl=" + lifetime.minimumAtl());
            System.out.println("             (advisory: honoured by conforming software, "
                    + "NOT enforced against a keyholder)");
            System.out.println("  disposal   at=" + lifetime.disposalAt()
                    + " action=" + lifetime.disposalAction());
            System.out.println("             (enforced by whoever stores the ciphertext)");
        }

        System.out.println("access_map:");
        List<Object> entries = Json.array(header, "access_map");
        if (entries == null) {
            entries = Json.array(cell, "recipients");
        }
        if (entries != null) {
            for (Object entryValue : entries) {
                Map<String, Object> entry = Json.asObject(entryValue);
                String share = entry.containsKey("share_index")
                        ? "  share " + Json.integer(entry, "share_index", 0) : "";
                System.out.printf("  - %-12s %s  \"%s\"%s%n",
                        Json.string(entry, "method"), Json.string(entry, "fingerprint"),
                        Json.string(entry, "label"), share);
            }
        }

        Map<String, Object> payload = Json.object(cell, "payload");
        if (payload == null) {
            payload = Json.object(cell, "encrypted_body");
        }
        if (payload != null) {
            String ct = Json.string(payload, "ciphertext");
            if (ct == null) {
                ct = Json.string(payload, "ct");
            }
            if (ct != null) {
                System.out.println("ciphertext   "
                        + CellCrypto.decodeB64(ct, "ciphertext").length
                        + " bytes (" + Json.string(payload, "alg") + ")");
            }
        }
        System.out.println();
        System.out.println(
                "not visible here: the plaintext, the filename, the media type, the original");
        System.out.println(
                "size, and any sender-defined meta — all of them live inside the ciphertext (§5).");
    }

    // ─── open ───────────────────────────────────────────────────────────────

    private static void open(Args args) throws Exception {
        String path = args.positional(0);
        if (path == null) {
            throw new CellException("usage: cdcell open CELL --key KEY.cdkey");
        }
        Cell.OpenOptions opts = new Cell.OpenOptions();
        opts.expectedSigner = args.one("expect-signer", null);
        opts.ignoreAdvisory = args.has("ignore-advisory");
        for (String keyPath : args.many("key")) {
            opts.keys.add(KeyRecord.fromCdkey(
                    Json.asObject(Json.parse(Files.readAllBytes(Path.of(keyPath))))));
        }
        if (args.has("passphrase")) {
            opts.passphrases.add(promptPassphrase("Passphrase: "));
        }

        Cell.OpenResult result = Cell.open(readCell(Path.of(path)), opts);

        // A trailing separator means "into this directory" even if it does not
        // exist yet; the filename is only known once the manifest is decrypted
        // (§5), so the caller cannot always name the output file in advance.
        String out = args.one("out", ".");
        Path destination = Path.of(out);
        if (Files.isDirectory(destination) || out.endsWith("/")) {
            Files.createDirectories(destination);
            destination = destination.resolve(Path.of(result.filename()).getFileName());
        }
        Files.write(destination, result.data());

        System.out.println("wrote " + destination + "  (" + result.data().length
                + " bytes, " + result.contentType() + ")");
        if (result.signed()) {
            System.out.println("signed by key " + result.signerFingerprint());
        }
        if (result.meta() != null) {
            System.out.println("sender meta: " + Canonical.canonicalize(result.meta()));
        }
    }

    // ─── helpers ────────────────────────────────────────────────────────────

    /** Read a {@code .cell} or a gzip-compressed {@code .celz} (spec §3). */
    private static Map<String, Object> readCell(Path path) throws Exception {
        byte[] raw = Files.readAllBytes(path);
        if (raw.length > 2 && (raw[0] & 0xFF) == 0x1f && (raw[1] & 0xFF) == 0x8b) {
            try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(raw))) {
                raw = gzip.readAllBytes();
            }
        }
        return Json.asObject(Json.parse(raw));
    }

    private static void writeCell(Path path, Map<String, Object> cell) throws Exception {
        byte[] text = (Json.writePretty(cell) + "\n").getBytes(StandardCharsets.UTF_8);
        if (path.toString().endsWith(".celz")) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(buffer)) {
                gzip.write(text);
            }
            text = buffer.toByteArray();
        }
        Files.write(path, text);
    }

    private static String contentTypeFor(String path) {
        // A deliberately tiny table rather than probeContentType: the value is a
        // hint carried inside the ciphertext, not something the format acts on,
        // and the JDK's answer varies with the platform's mime database.
        int dot = path.lastIndexOf('.');
        String ext = dot < 0 ? "" : path.substring(dot + 1).toLowerCase(java.util.Locale.ROOT);
        return switch (ext) {
            case "txt", "md" -> "text/plain";
            case "json" -> "application/json";
            case "pdf" -> "application/pdf";
            case "png" -> "image/png";
            case "jpg", "jpeg" -> "image/jpeg";
            case "html" -> "text/html";
            case "csv" -> "text/csv";
            default -> "application/octet-stream";
        };
    }

    private static String promptPassphrase(String prompt) throws Exception {
        Console console = System.console();
        if (console != null) {
            char[] entered = console.readPassword(prompt);
            return entered == null ? "" : new String(entered);
        }
        // Not a terminal (a pipe, a test harness): read a line, echoed.
        System.err.print(prompt);
        java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line = reader.readLine();
        return line == null ? "" : line;
    }
}
