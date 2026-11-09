// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Sender-chosen filename and text (pen test 2026-11-09, M1/M2). */
class CdcellTest {

    @Test
    void safeFilename() {
        String[][] cases = {
            {"report.pdf", "report.pdf"}, {"../../etc/passwd", "passwd"}, {"a\\b\\c.txt", "c.txt"},
            {".bashrc", "bashrc"}, {". .envrc", "envrc"}, {"..", "decrypted"}, {"/", "decrypted"},
            {"", "decrypted"}, {"x\u0000y\nz", "xyz"}, {"contract\u202efdp.exe", "contractfdp.exe"},
            {"\ud800.txt", "txt"}, {"é".repeat(150), "é".repeat(100)},
        };
        for (String[] c : cases) {
            assertEquals(c[1], Cdcell.safeFilename(c[0]), c[0]);
        }
        assertEquals("decrypted", Cdcell.safeFilename(null));
    }

    @Test
    void shownEscapesWhatCouldForgeALine() {
        String got = Cdcell.shown("application/pdf\nsigned by key aff6a52990ce2335\u001b[8m\u202e");
        assertFalse(got.contains("\n") || got.contains("\u001b") || got.contains("\u202e"), got);
        assertTrue(got.contains("\\u000a") && got.contains("\\u001b") && got.contains("\\u202e"), got);
    }

    @Test
    void writeNewNeverOverwrites(@TempDir Path dir) throws Exception {
        Path mine = dir.resolve(".bashrc");
        Files.writeString(mine, "mine");
        assertThrows(CellException.class, () -> Cdcell.writeNew(mine, "attacker".getBytes()));
        assertEquals("mine", Files.readString(mine));

        Path link = dir.resolve("link");
        Files.createSymbolicLink(link, dir.resolve("elsewhere"));
        assertThrows(CellException.class, () -> Cdcell.writeNew(link, "attacker".getBytes()));
        assertFalse(Files.exists(dir.resolve("elsewhere")));

        Path fresh = dir.resolve("fresh");
        Cdcell.writeNew(fresh, "ok".getBytes());
        assertEquals("ok", Files.readString(fresh));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(fresh)));
    }
}
