//! Bencoding (BEP 3), read strictly and bounded: what the DHT sends is
//! from strangers, and anything not exactly one value is refused.

use std::collections::BTreeMap;

/// Deepest nesting read. A real message has three levels.
const MAX_DEPTH: usize = 8;
/// Elements one list or dictionary may have. A real one has a dozen.
const MAX_ITEMS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl Value {
    pub fn bytes(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }

    pub fn dict(items: Vec<(&str, Value)>) -> Self {
        Value::Dict(
            items
                .into_iter()
                .map(|(k, v)| (k.as_bytes().to_vec(), v))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(d) => d.get(key.as_bytes()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }
}

/// Writes a value the one way bencoding allows: dictionary keys sorted.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    put(v, &mut out);
    out
}

fn put(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        Value::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Value::List(l) => {
            out.push(b'l');
            l.iter().for_each(|x| put(x, out));
            out.push(b'e');
        }
        Value::Dict(d) => {
            out.push(b'd');
            for (k, x) in d {
                out.extend_from_slice(k.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                put(x, out);
            }
            out.push(b'e');
        }
    }
}

/// Reads one value, with nothing after it. Integers are written the
/// canonical way (no leading zeros, no "-0"), a dictionary key is a byte
/// string that appears once, and nothing is nested deeper than
/// `MAX_DEPTH` levels or longer than `MAX_ITEMS`. The order of a dictionary's
/// keys is not insisted on: some real implementations get it wrong, and
/// nothing here depends on it.
pub fn decode(data: &[u8]) -> Option<Value> {
    let mut pos = 0;
    let v = take(data, &mut pos, 0)?;
    (pos == data.len()).then_some(v)
}

fn take(data: &[u8], pos: &mut usize, depth: usize) -> Option<Value> {
    if depth > MAX_DEPTH {
        return None;
    }
    match *data.get(*pos)? {
        b'i' => {
            *pos += 1;
            let end = data[*pos..].iter().position(|&b| b == b'e')? + *pos;
            let digits = std::str::from_utf8(&data[*pos..end]).ok()?;
            let canonical = match digits.strip_prefix('-') {
                Some(rest) => !rest.starts_with('0') && !rest.is_empty(),
                None => digits == "0" || !digits.starts_with('0') && !digits.is_empty(),
            };
            if !canonical || digits.len() > 20 {
                return None;
            }
            *pos = end + 1;
            Some(Value::Int(digits.parse().ok()?))
        }
        b'l' => {
            *pos += 1;
            let mut items = Vec::new();
            while *data.get(*pos)? != b'e' {
                if items.len() >= MAX_ITEMS {
                    return None;
                }
                items.push(take(data, pos, depth + 1)?);
            }
            *pos += 1;
            Some(Value::List(items))
        }
        b'd' => {
            *pos += 1;
            let mut items = BTreeMap::new();
            while *data.get(*pos)? != b'e' {
                if items.len() >= MAX_ITEMS {
                    return None;
                }
                let Value::Bytes(key) = take_bytes(data, pos)? else {
                    return None;
                };
                let value = take(data, pos, depth + 1)?;
                if items.insert(key, value).is_some() {
                    return None;
                }
            }
            *pos += 1;
            Some(Value::Dict(items))
        }
        b'0'..=b'9' => take_bytes(data, pos),
        _ => None,
    }
}

fn take_bytes(data: &[u8], pos: &mut usize) -> Option<Value> {
    let colon = data[*pos..].iter().position(|&b| b == b':')? + *pos;
    let digits = std::str::from_utf8(&data[*pos..colon]).ok()?;
    if digits.is_empty()
        || digits.len() > 6
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let len: usize = digits.parse().ok()?;
    let start = colon + 1;
    let end = start.checked_add(len)?;
    let bytes = data.get(start..end)?.to_vec();
    *pos = end;
    Some(Value::Bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_written_is_read_back() {
        let v = Value::dict(vec![
            ("a", Value::Int(-42)),
            ("b", Value::bytes(b"spam")),
            (
                "c",
                Value::List(vec![Value::Int(0), Value::bytes(b""), Value::dict(vec![])]),
            ),
        ]);
        let bytes = encode(&v);
        assert_eq!(bytes, b"d1:ai-42e1:b4:spam1:cli0e0:deee");
        assert_eq!(decode(&bytes), Some(v));
    }

    #[test]
    fn only_a_canonical_single_value_is_read() {
        for bad in [
            &b"i03e"[..],
            b"i-0e",
            b"i-e",
            b"ie",
            b"i1",
            b"i1ee",
            b"03:abc",
            b"3:ab",
            b"-1:a",
            b":",
            b"l",
            b"d1:a",
            b"di1ei2ee",
            b"d1:ai1e1:ai2ee",
            b"x",
            b"",
            b"i99999999999999999999999e",
            b"1234567:a",
        ] {
            assert_eq!(decode(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        // Keys out of order are read (real nodes send them).
        assert!(decode(b"d1:bi1e1:ai2ee").is_some());
        // Nothing after the value.
        assert_eq!(decode(b"i1ei2e"), None);
    }

    #[test]
    fn nesting_and_length_are_bounded() {
        let deep = format!("{}{}", "l".repeat(MAX_DEPTH + 2), "e".repeat(MAX_DEPTH + 2));
        assert_eq!(decode(deep.as_bytes()), None);
        let ok = format!("{}{}", "l".repeat(MAX_DEPTH), "e".repeat(MAX_DEPTH));
        assert!(decode(ok.as_bytes()).is_some());
        let wide = format!("l{}e", "i1e".repeat(MAX_ITEMS + 1));
        assert_eq!(decode(wide.as_bytes()), None);
        // A length that claims more than there is allocates nothing.
        assert_eq!(decode(b"999999:abc"), None);
    }

    #[test]
    fn nothing_a_stranger_sends_panics() {
        let good = encode(&Value::dict(vec![
            ("t", Value::bytes(b"aa")),
            ("y", Value::bytes(b"r")),
            ("r", Value::dict(vec![("id", Value::bytes(&[7; 20]))])),
        ]));
        for n in 0..good.len() {
            let _ = decode(&good[..n]);
        }
        for i in 0..good.len() {
            for v in [0u8, b'e', b'i', b'd', b'l', b':', b'9', 0xff] {
                let mut bad = good.clone();
                bad[i] = v;
                let _ = decode(&bad);
            }
        }
    }
}
