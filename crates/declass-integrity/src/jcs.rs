// SPDX-License-Identifier: GPL-3.0-or-later
//! The JSON Canonicalization Scheme (RFC 8785): one byte sequence for every
//! JSON value, whatever order or spelling it arrived in. Object members are
//! sorted by the UTF-16 code units of their names, strings use the fewest
//! escapes, and numbers are written as ECMAScript writes a double.

use serde_json::{Number, Value};
use std::fmt::Write as _;

/// The canonical form of `value`.
pub fn canonical(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write(value, &mut out);
    out.into_bytes()
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)),
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            // Explicitly: serde_json keeps insertion order here (`preserve_order`).
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (name, member)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(name, out);
                out.push(':');
                write(member, out);
            }
            out.push('}');
        }
    }
}

/// Escapes only `"`, `\` and control characters (`\b \t \n \f \r`, the rest
/// as `\u00xx`); everything else is written as is.
fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON number as the IEEE double it denotes, written as ECMAScript's
/// `Number.prototype.toString` writes it (integers beyond 2^53 lose their
/// low digits, as they do in every JavaScript implementation).
fn number(n: &Number) -> String {
    let f = n
        .as_f64()
        .or_else(|| n.as_i64().map(|i| i as f64))
        .or_else(|| n.as_u64().map(|u| u as f64))
        .unwrap_or(0.0);
    ecmascript(f)
}

fn ecmascript(f: f64) -> String {
    if f == 0.0 || !f.is_finite() {
        // -0 is written 0; JSON has no NaN or infinity.
        return "0".to_owned();
    }
    let sign = if f < 0.0 { "-" } else { "" };
    // The shortest digits that read back as `f` (what ECMAScript requires),
    // from ryu's own notation: `d.ddd`, `d.ddde±x` or `de±x`.
    let mut buffer = ryu::Buffer::new();
    let shortest = buffer.format_finite(f.abs());
    let (mantissa, exponent) = match shortest.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>().unwrap_or(0)),
        None => (shortest, 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = format!("{int_part}{frac_part}");
    // n: where the decimal point falls in the digit string (ECMA-262's n).
    let mut n = int_part.len() as i32 + exponent;
    let leading = digits.len() - digits.trim_start_matches('0').len();
    digits.drain(..leading);
    n -= leading as i32;
    let trimmed = digits.trim_end_matches('0').len();
    digits.truncate(trimmed);
    let k = digits.len() as i32;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let e = if e < 0 {
            format!("-{}", -e)
        } else {
            format!("+{e}")
        };
        if k == 1 {
            format!("{digits}e{e}")
        } else {
            format!("{}.{}e{e}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text(v: &Value) -> String {
        String::from_utf8(canonical(v)).unwrap()
    }

    /// RFC 8785 appendix B: IEEE double values and their canonical text.
    #[test]
    fn numbers_follow_the_rfc_samples() {
        for (bits, want) in [
            (0x0000000000000000u64, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ] {
            assert_eq!(ecmascript(f64::from_bits(bits)), want, "{bits:#x}");
        }
        assert_eq!(
            text(&json!([1, -7, 1.5, 100.0, 1e-7, 12345678901234567890u64])),
            "[1,-7,1.5,100,1e-7,12345678901234567000]"
        );
    }

    /// RFC 8785 3.2.3: names sorted by UTF-16 code units, where a character
    /// outside the BMP (a surrogate pair) sorts before U+FB33.
    #[test]
    fn object_members_sort_by_utf16_code_units() {
        let v = json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{80}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis"
        });
        let order: Vec<String> = {
            let t = text(&v);
            let parsed: serde_json::Map<String, Value> = serde_json::from_str(&t).unwrap();
            parsed
                .values()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            order,
            [
                "Carriage Return",
                "One",
                "Control",
                "Latin Small Letter O With Diaeresis",
                "Euro Sign",
                "Emoji: Grinning Face",
                "Hebrew Letter Dalet With Dagesh"
            ]
        );
    }

    /// RFC 8785 3.2.2: the sample with numbers, literals and escapes.
    #[test]
    fn the_rfc_sample_is_reproduced() {
        let v: Value = serde_json::from_str(
            r#"{
              "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
              "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
              "literals": [null, true, false]
            }"#,
        )
        .unwrap();
        assert_eq!(
            text(&v),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":[1,2],"x":"s"}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":"s","y":[1,2]},"b":1.0}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(text(&a), r#"{"a":{"x":"s","y":[1,2]},"b":1}"#);
    }
}
