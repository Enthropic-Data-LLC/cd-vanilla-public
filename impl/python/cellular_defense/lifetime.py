# SPDX-FileCopyrightText: 2026 Enthropic Data LLC
# SPDX-License-Identifier: Apache-2.0
"""Lifetime model — spec §8.

v1.3 splits `lifetime` by *who enforces it*, and the split is the point:

``advisory``
    What conforming software does. **Not enforced against a keyholder.** A
    recipient who holds a qualifying key can ignore every value here — by
    editing their client, or by writing an opener from the specification, which
    is precisely what this library is. Passing ``enforce_advisory=False`` to
    :func:`.cell.cell_open` is therefore not a backdoor; it is the honest
    surface of a property the format has always had. What the AAD binding of
    §4.4 does give you is that a *third party* cannot alter or strip these
    values undetected: the recipient is guaranteed to see the sender's true
    instructions, and nothing more.

``disposal``
    What the party storing the ciphertext does with it, on schedule, without
    reading it. This half is genuinely enforced, against everyone who has not
    already taken a copy. It is not a statement about the recipient's
    permission, and clients MUST NOT refuse to open a cell on the basis of it.

v1.0-v1.2 cells carry a flat shape (``expires_at``/``on_expiry``) and are read
under their own rules; :func:`normalize` maps them onto the v1.3 shape without
changing what their author intended.
"""

from __future__ import annotations

from dataclasses import dataclass

PERMANENT: dict = {
    "type": "permanent",
    "advisory": {"retain_until": None, "release_at": None, "single_use": False, "minimum_atl": 1},
    "disposal": {"at": None, "action": "none"},
}


def normalize(lt: dict | None) -> dict | None:
    """Return the v1.3 shape, accepting either it or the flat v1.0-v1.2 shape."""
    if not lt:
        return None
    if "advisory" in lt or "disposal" in lt:
        advisory = lt.get("advisory") or {}
        disposal = lt.get("disposal") or {}
        return {
            "type": lt.get("type") or "permanent",
            "advisory": {
                "retain_until": advisory.get("retain_until"),
                "release_at": advisory.get("release_at"),
                "single_use": advisory.get("single_use", False),
                "minimum_atl": advisory.get("minimum_atl", 1),
            },
            "disposal": {
                "at": disposal.get("at"),
                "action": disposal.get("action") or "none",
            },
        }
    # Flat legacy shape. `expires_at` served both roles at once — that conflation
    # is what v1.3 exists to undo — so it lands in both halves here, preserving
    # the behaviour the cell's author actually got.
    return {
        "type": lt.get("type") or "permanent",
        "advisory": {
            "retain_until": lt.get("expires_at"),
            "release_at": lt.get("release_at"),
            "single_use": lt.get("single_use", False),
            # Application code once called this minimum_etl; minimum_atl is canonical (§8.1).
            "minimum_atl": lt.get("minimum_atl", lt.get("minimum_etl", 1)),
        },
        "disposal": {"at": lt.get("expires_at"), "action": lt.get("on_expiry") or "none"},
    }


@dataclass(frozen=True)
class Lifetime:
    """Version-agnostic read of either lifetime shape."""

    type: str
    retain_until: int | None
    release_at: int | None
    single_use: bool
    minimum_atl: int
    disposal_at: int | None
    disposal_action: str


def read(lt: dict | None) -> Lifetime | None:
    n = normalize(lt)
    if n is None:
        return None
    return Lifetime(
        type=n["type"],
        retain_until=n["advisory"]["retain_until"],
        release_at=n["advisory"]["release_at"],
        single_use=n["advisory"]["single_use"],
        minimum_atl=n["advisory"]["minimum_atl"],
        disposal_at=n["disposal"]["at"],
        disposal_action=n["disposal"]["action"],
    )
