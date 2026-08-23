// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

//! Lifetime model — spec §8.
//!
//! v1.3 splits `lifetime` by **who enforces it**, and the split is the point.
//!
//! `advisory` is what conforming software does. It is **not enforced against a
//! keyholder** — a recipient holding a qualifying key can ignore every value
//! here, by editing their client or by writing an opener from the
//! specification, which is exactly what this crate is. What the AAD binding of
//! §4.4 gives you is narrower and worth stating exactly: a third party cannot
//! alter or strip these values undetected, so the recipient is guaranteed to
//! see the sender's true instructions. Nothing obliges them to follow them.
//!
//! `disposal` is what the party **storing** the ciphertext does with it, on
//! schedule, without reading it. That half is genuinely enforced, against
//! everyone who has not already taken a copy. It says nothing about the
//! recipient's permission, and clients MUST NOT refuse to open a cell on the
//! basis of it.

use serde_json::{json, Map, Value};

/// A version-agnostic read of either lifetime shape.
#[derive(Debug, Clone, PartialEq)]
pub struct Lifetime {
    pub type_: String,
    pub retain_until: Option<i64>,
    pub release_at: Option<i64>,
    pub single_use: bool,
    pub minimum_atl: i64,
    pub disposal_at: Option<i64>,
    pub disposal_action: String,
}

fn opt_int(map: &Value, key: &str) -> Option<i64> {
    map.get(key).and_then(|v| v.as_i64())
}

/// Read either the v1.3 split shape or the flat v1.0-v1.2 shape.
pub fn read(lifetime: Option<&Value>) -> Option<Lifetime> {
    let lt = lifetime?;
    if !lt.is_object() {
        return None;
    }
    let type_ = lt
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("permanent")
        .to_string();

    let advisory = lt.get("advisory").filter(|v| v.is_object());
    let disposal = lt.get("disposal").filter(|v| v.is_object());

    if advisory.is_some() || disposal.is_some() {
        let empty = Value::Object(Map::new());
        let a = advisory.unwrap_or(&empty);
        let d = disposal.unwrap_or(&empty);
        return Some(Lifetime {
            type_,
            retain_until: opt_int(a, "retain_until"),
            release_at: opt_int(a, "release_at"),
            single_use: a.get("single_use").and_then(|v| v.as_bool()).unwrap_or(false),
            minimum_atl: opt_int(a, "minimum_atl").unwrap_or(1),
            disposal_at: opt_int(d, "at"),
            disposal_action: d
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("none")
                .to_string(),
        });
    }

    // Flat legacy shape. `expires_at` served both roles at once — that
    // conflation is what v1.3 exists to undo — so it lands in both halves here,
    // preserving the behaviour the cell's author actually got.
    Some(Lifetime {
        type_,
        retain_until: opt_int(lt, "expires_at"),
        release_at: opt_int(lt, "release_at"),
        single_use: lt.get("single_use").and_then(|v| v.as_bool()).unwrap_or(false),
        // Application code once called this minimum_etl; minimum_atl is
        // canonical for the format (§8.1).
        minimum_atl: opt_int(lt, "minimum_atl")
            .or_else(|| opt_int(lt, "minimum_etl"))
            .unwrap_or(1),
        disposal_at: opt_int(lt, "expires_at"),
        disposal_action: lt
            .get("on_expiry")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_string(),
    })
}

/// Return the v1.3 shape, accepting either it or the flat one.
pub fn normalize(lifetime: Option<&Value>) -> Option<Value> {
    let lt = read(lifetime)?;
    Some(json!({
        "type": lt.type_,
        "advisory": {
            "retain_until": lt.retain_until,
            "release_at": lt.release_at,
            "single_use": lt.single_use,
            "minimum_atl": lt.minimum_atl,
        },
        "disposal": {
            "at": lt.disposal_at,
            "action": lt.disposal_action,
        },
    }))
}

/// The default: no end date, nothing to enforce.
pub fn permanent() -> Value {
    json!({
        "type": "permanent",
        "advisory": {
            "retain_until": Value::Null,
            "release_at": Value::Null,
            "single_use": false,
            "minimum_atl": 1,
        },
        "disposal": { "at": Value::Null, "action": "none" },
    })
}
