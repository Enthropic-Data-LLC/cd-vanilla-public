// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

// Lifetime model — spec §8.
//
// v1.3 splits lifetime by WHO ENFORCES IT, and the split is the point.
//
// advisory: what conforming software does. NOT enforced against a keyholder — a
// recipient holding a qualifying key can ignore every value here, by editing
// their client or by writing an opener from the specification, which is exactly
// what this package is. What the AAD binding of §4.4 gives you is narrower and
// worth stating exactly: a third party cannot alter or strip these values
// undetected, so the recipient is guaranteed to see the sender's true
// instructions. Nothing obliges them to follow them.
//
// disposal: what the party STORING the ciphertext does with it, on schedule,
// without reading it. This half is genuinely enforced, against everyone who has
// not already taken a copy. It says nothing about the recipient's permission,
// and clients MUST NOT refuse to open a cell on the basis of it.

// Lifetime is a version-agnostic read of either lifetime shape.
type Lifetime struct {
	Type           string
	RetainUntil    int64
	ReleaseAt      int64
	SingleUse      bool
	MinimumATL     int
	DisposalAt     int64
	DisposalAction string
}

func optInt(o *Object, key string) int64 {
	v, ok := o.Get(key)
	if !ok || v == nil {
		return 0
	}
	f, ok := v.(float64)
	if !ok {
		return 0
	}
	return int64(f)
}

func optBool(o *Object, key string, fallback bool) bool {
	v, ok := o.Get(key)
	if !ok || v == nil {
		return fallback
	}
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

// ReadLifetime accepts either the v1.3 split shape or the flat v1.0-v1.2 shape.
func ReadLifetime(lt *Object) *Lifetime {
	if lt == nil {
		return nil
	}
	out := &Lifetime{Type: "permanent", MinimumATL: 1, DisposalAction: "none"}
	if t := lt.GetString("type"); t != "" {
		out.Type = t
	}

	advisory := lt.GetObject("advisory")
	disposal := lt.GetObject("disposal")
	if advisory != nil || disposal != nil {
		if advisory != nil {
			out.RetainUntil = optInt(advisory, "retain_until")
			out.ReleaseAt = optInt(advisory, "release_at")
			out.SingleUse = optBool(advisory, "single_use", false)
			out.MinimumATL = advisory.GetInt("minimum_atl", 1)
		}
		if disposal != nil {
			out.DisposalAt = optInt(disposal, "at")
			if action := disposal.GetString("action"); action != "" {
				out.DisposalAction = action
			}
		}
		return out
	}

	// Flat legacy shape. expires_at served both roles at once — that conflation
	// is what v1.3 exists to undo — so it lands in both halves here, preserving
	// the behaviour the cell's author actually got.
	out.RetainUntil = optInt(lt, "expires_at")
	out.ReleaseAt = optInt(lt, "release_at")
	out.SingleUse = optBool(lt, "single_use", false)
	// Application code once called this minimum_etl; minimum_atl is canonical (§8.1).
	out.MinimumATL = lt.GetInt("minimum_atl", lt.GetInt("minimum_etl", 1))
	out.DisposalAt = optInt(lt, "expires_at")
	if action := lt.GetString("on_expiry"); action != "" {
		out.DisposalAction = action
	}
	return out
}

// NormalizeLifetime returns the v1.3 shape, accepting either it or the flat one.
func NormalizeLifetime(lt *Object) *Object {
	read := ReadLifetime(lt)
	if read == nil {
		return nil
	}
	advisory := NewObject()
	advisory.Set("retain_until", nullableInt(read.RetainUntil))
	advisory.Set("release_at", nullableInt(read.ReleaseAt))
	advisory.Set("single_use", read.SingleUse)
	advisory.Set("minimum_atl", float64(read.MinimumATL))

	disposal := NewObject()
	disposal.Set("at", nullableInt(read.DisposalAt))
	disposal.Set("action", read.DisposalAction)

	out := NewObject()
	out.Set("type", read.Type)
	out.Set("advisory", advisory)
	out.Set("disposal", disposal)
	return out
}

// PermanentLifetime is the default: no end date, nothing to enforce.
func PermanentLifetime() *Object {
	return NormalizeLifetime(NewObject())
}

func nullableInt(v int64) Value {
	if v == 0 {
		return nil
	}
	return float64(v)
}
