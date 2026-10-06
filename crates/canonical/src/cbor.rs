//! Deterministic CBOR по RFC 8949 §4.2.1 (core deterministic encoding).
//!
//! Отличия от RFC 7049 существенны: сортировка ключей map — байтовая по
//! **закодированному** ключу, а не по длине-затем-значению. Реализация
//! умышленно не использует общий CBOR-крейт: нормативен здесь один
//! конкретный профиль, а не «какой-нибудь валидный CBOR».
//!
//! Профиль OneLayer:
//!   * floats запрещены полностью — decimal передаётся строкой с фиксированным
//!     scale (§4.1 плана), поэтому недетерминированного binary64 быть не может;
//!   * indefinite-length кодирование запрещено;
//!   * строки нормализуются в NFC до кодирования, длина считается в байтах UTF-8;
//!   * отсутствующий ключ и `null` различаются: `null` кодируется как 0xf6,
//!     отсутствующий ключ в map не появляется.

use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Целое; диапазон CBOR шире i64, поэтому i128.
    Int(i128),
    /// Текст. Нормализуется в NFC при кодировании.
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    /// Ключи — только текстовые: канонические записи не используют иных ключей,
    /// а смешанные типы ключей усложнили бы правило сортировки без пользы.
    Map(BTreeMap<String, Value>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Целое вне диапазона, представимого CBOR major type 0/1.
    IntOutOfRange(i128),
}

impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CborError::IntOutOfRange(v) => {
                write!(f, "CANONICALIZATION_FAILED: целое вне диапазона CBOR: {v}")
            }
        }
    }
}

impl std::error::Error for CborError {}

/// NFC-нормализация. Применяется ко всем строкам до измерения длины.
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// Детерминированная сериализация значения.
pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), CborError> {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Int(v) => encode_int(*v, out)?,
        Value::Text(s) => {
            let bytes = nfc(s).into_bytes();
            head(3, bytes.len() as u64, out);
            out.extend_from_slice(&bytes);
        }
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Map(entries) => {
            // Ключи сортируются по байтам их закодированного представления.
            // BTreeMap<String> даёт порядок по строкам — этого недостаточно:
            // при разной длине заголовок ключа меняет байтовый порядок.
            let mut encoded: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                encoded.push((encode(&Value::Text(k.clone()))?, v));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            head(5, encoded.len() as u64, out);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                encode_into(v, out)?;
            }
        }
    }
    Ok(())
}

fn encode_int(v: i128, out: &mut Vec<u8>) -> Result<(), CborError> {
    if v >= 0 {
        let u = u64::try_from(v).map_err(|_| CborError::IntOutOfRange(v))?;
        head(0, u, out);
    } else {
        // major type 1 кодирует -1-n
        let n = -(v + 1);
        let u = u64::try_from(n).map_err(|_| CborError::IntOutOfRange(v))?;
        head(1, u, out);
    }
    Ok(())
}

/// Заголовок: major type + argument в кратчайшей форме.
fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    match arg {
        0..=23 => out.push(mt | arg as u8),
        24..=0xff => {
            out.push(mt | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(mt | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(mt | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(mt | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &Value) -> String {
        hex::encode(encode(v).unwrap())
    }

    #[test]
    fn ints_shortest_form() {
        assert_eq!(hex(&Value::Int(0)), "00");
        assert_eq!(hex(&Value::Int(23)), "17");
        assert_eq!(hex(&Value::Int(24)), "1818");
        assert_eq!(hex(&Value::Int(255)), "18ff");
        assert_eq!(hex(&Value::Int(256)), "190100");
        assert_eq!(hex(&Value::Int(65536)), "1a00010000");
        assert_eq!(hex(&Value::Int(4294967296)), "1b0000000100000000");
        assert_eq!(hex(&Value::Int(-1)), "20");
        assert_eq!(hex(&Value::Int(-24)), "37");
        assert_eq!(hex(&Value::Int(-25)), "3818");
        assert_eq!(hex(&Value::Int(-256)), "38ff");
    }

    #[test]
    fn int_out_of_range_rejected() {
        let too_big = i128::from(u64::MAX) + 1;
        assert_eq!(
            encode(&Value::Int(too_big)),
            Err(CborError::IntOutOfRange(too_big))
        );
    }

    #[test]
    fn simple_values() {
        assert_eq!(hex(&Value::Null), "f6");
        assert_eq!(hex(&Value::Bool(true)), "f5");
        assert_eq!(hex(&Value::Bool(false)), "f4");
    }

    #[test]
    fn text_is_nfc_normalized_before_encoding() {
        // "й" в двух формах: precomposed U+0439 и U+0438 U+0306.
        let composed = Value::Text("\u{0439}".into());
        let decomposed = Value::Text("\u{0438}\u{0306}".into());
        assert_eq!(hex(&composed), hex(&decomposed));
        // 2 байта UTF-8, не 1 code point и не 2 code points
        assert_eq!(hex(&composed), "62d0b9");
    }

    #[test]
    fn armenian_combining_normalized() {
        // Армянское "և" (U+0587) под NFC не разлагается (разлагает только NFKC).
        // 2 байта UTF-8 — контроль отсутствия ложной совместимой декомпозиции.
        assert_eq!(hex(&Value::Text("\u{0587}".into())), "62d687");
        assert_ne!(
            hex(&Value::Text("\u{0587}".into())),
            hex(&Value::Text("\u{0565}\u{0582}".into()))
        );
    }

    #[test]
    fn map_keys_sorted_by_encoded_bytes_not_by_string() {
        // "z" (0x617a) короче, чем "aa" (0x626161)? Нет: заголовок длины
        // делает однобуквенный ключ меньше двухбуквенного независимо от букв.
        let mut m = BTreeMap::new();
        m.insert("aa".to_string(), Value::Int(1));
        m.insert("z".to_string(), Value::Int(2));
        // По строкам: "aa" < "z". По закодированным байтам: 617a < 626161, то есть "z" первый.
        assert_eq!(hex(&Value::Map(m)), "a2617a0262616101");
    }

    #[test]
    fn null_differs_from_absent_key() {
        let mut with_null = BTreeMap::new();
        with_null.insert("a".to_string(), Value::Null);
        let absent: BTreeMap<String, Value> = BTreeMap::new();
        assert_ne!(hex(&Value::Map(with_null)), hex(&Value::Map(absent)));
    }

    #[test]
    fn array_order_is_significant() {
        let a = Value::Array(vec![Value::Int(1), Value::Int(2)]);
        let b = Value::Array(vec![Value::Int(2), Value::Int(1)]);
        assert_ne!(hex(&a), hex(&b));
        assert_eq!(hex(&Value::Array(vec![])), "80");
    }

    #[test]
    fn decimal_is_text_so_scale_is_preserved() {
        assert_ne!(
            hex(&Value::Text("0.10".into())),
            hex(&Value::Text("0.1".into()))
        );
        assert_ne!(
            hex(&Value::Text("-0".into())),
            hex(&Value::Text("0".into()))
        );
    }

    #[test]
    fn surrogate_pair_encoded_as_four_utf8_bytes() {
        // U+1F600 — вне BMP; в UTF-16 это суррогатная пара, в UTF-8 — 4 байта.
        assert_eq!(hex(&Value::Text("\u{1F600}".into())), "64f09f9880");
    }

    #[test]
    fn rtl_marker_is_significant() {
        assert_ne!(
            hex(&Value::Text("a\u{200F}b".into())),
            hex(&Value::Text("ab".into()))
        );
    }
}
