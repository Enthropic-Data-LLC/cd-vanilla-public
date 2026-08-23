// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package com.enthropicdata.cell;

import java.util.Map;

/**
 * Lifetime model — spec §8.
 *
 * <p>v1.3 splits {@code lifetime} by <b>who enforces it</b>, and the split is
 * the point.
 *
 * <p>{@code advisory} is what conforming software does. It is <b>not enforced
 * against a keyholder</b> — a recipient holding a qualifying key can ignore
 * every value here, by editing their client or by writing an opener from the
 * specification, which is exactly what this library is. What the AAD binding of
 * §4.4 gives you is narrower and worth stating exactly: a third party cannot
 * alter or strip these values undetected, so the recipient is guaranteed to see
 * the sender's true instructions. Nothing obliges them to follow them.
 *
 * <p>{@code disposal} is what the party <b>storing</b> the ciphertext does with
 * it, on schedule, without reading it. That half is genuinely enforced, against
 * everyone who has not already taken a copy. It says nothing about the
 * recipient's permission, and clients MUST NOT refuse to open a cell on the
 * basis of it.
 */
public record Lifetime(
        String type,
        Long retainUntil,
        Long releaseAt,
        boolean singleUse,
        long minimumAtl,
        Long disposalAt,
        String disposalAction) {

    /** Read either the v1.3 split shape or the flat v1.0-v1.2 shape. */
    public static Lifetime read(Map<String, Object> lifetime) {
        if (lifetime == null) {
            return null;
        }
        String type = orDefault(Json.string(lifetime, "type"), "permanent");
        Map<String, Object> advisory = Json.object(lifetime, "advisory");
        Map<String, Object> disposal = Json.object(lifetime, "disposal");

        if (advisory != null || disposal != null) {
            return new Lifetime(
                    type,
                    Json.optionalInteger(advisory, "retain_until"),
                    Json.optionalInteger(advisory, "release_at"),
                    Json.bool(advisory, "single_use", false),
                    Json.integer(advisory, "minimum_atl", 1),
                    Json.optionalInteger(disposal, "at"),
                    orDefault(Json.string(disposal, "action"), "none"));
        }

        // Flat legacy shape. expires_at served both roles at once — that
        // conflation is what v1.3 exists to undo — so it lands in both halves
        // here, preserving the behaviour the cell's author actually got.
        Long expiresAt = Json.optionalInteger(lifetime, "expires_at");
        long minimumAtl = Json.integer(lifetime, "minimum_atl",
                // Application code once called this minimum_etl; minimum_atl is
                // canonical for the format (§8.1).
                Json.integer(lifetime, "minimum_etl", 1));
        return new Lifetime(
                type,
                expiresAt,
                Json.optionalInteger(lifetime, "release_at"),
                Json.bool(lifetime, "single_use", false),
                minimumAtl,
                expiresAt,
                orDefault(Json.string(lifetime, "on_expiry"), "none"));
    }

    /** Return the v1.3 shape, accepting either it or the flat one. */
    public static Map<String, Object> normalize(Map<String, Object> lifetime) {
        Lifetime read = read(lifetime);
        if (read == null) {
            return null;
        }
        return Json.of(
                "type", read.type(),
                "advisory", Json.of(
                        "retain_until", asDouble(read.retainUntil()),
                        "release_at", asDouble(read.releaseAt()),
                        "single_use", read.singleUse(),
                        "minimum_atl", (double) read.minimumAtl()),
                "disposal", Json.of(
                        "at", asDouble(read.disposalAt()),
                        "action", read.disposalAction()));
    }

    /** The default: no end date, nothing to enforce. */
    public static Map<String, Object> permanent() {
        return normalize(Json.of("type", "permanent"));
    }

    private static Double asDouble(Long value) {
        return value == null ? null : (double) value;
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }
}
