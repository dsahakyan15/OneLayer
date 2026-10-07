//! Canonical JSON + domain-separated SHA-256 для audit-событий, цепочки sink и
//! evidence bundle. Каноническая форма: рекурсивная сортировка ключей объектов
//! (UTF-8 code units), компактная запись без пробелов, строки — стандартный
//! JSON escaping. Одна и та же форма используется при записи, replay и export,
//! поэтому hash не зависит от порядка ключей в сериализаторе.

use serde_json::Value as Json;
use sha2::{Digest, Sha256};

fn push_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn canonical_json(value: &Json) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(n) => out.push_str(&n.to_string()),
        Json::String(s) => push_string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Json::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_string(k, out);
                out.push(':');
                write_value(&map[*k], out);
            }
            out.push('}');
        }
    }
}

pub fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_and_is_stable() {
        let a = canonical_json(&json!({"b": 1, "a": {"z": [1, "x\n"], "y": null}}));
        assert_eq!(a, "{\"a\":{\"y\":null,\"z\":[1,\"x\\n\"]},\"b\":1}");
        let b = canonical_json(&json!({"a": {"y": null, "z": [1, "x\n"]}, "b": 1}));
        assert_eq!(a, b);
    }
}
