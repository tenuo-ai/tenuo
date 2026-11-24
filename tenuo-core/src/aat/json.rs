//! JSON reading for AAT tokens.
//!
//! Section 8 needs three things a general-purpose JSON value drops: whether an
//! object repeats a member name, whether a number was written with a fraction
//! or exponent part (Section 3.2), and whether a number survives the trip
//! through an IEEE 754 double that JCS forces on it (Section 3.4). This reader
//! keeps every number's text, so all three can be answered after parsing.

use std::collections::HashSet;

/// Nesting limit of the reader. A constraint tree at the default
/// `MAX_CONSTRAINT_DEPTH` nests about 70 levels, so this leaves the depth
/// check of steps 3n and 4o to report its own failure.
const MAX_NESTING: usize = 512;

#[derive(Debug, Clone)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Num(Num),
    Str(String),
    Arr(Vec<Json>),
    Obj(Obj),
}

impl Json {
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_obj(&self) -> Option<&Obj> {
        match self {
            Json::Obj(o) => Some(o),
            _ => None,
        }
    }

    pub(crate) fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub(crate) fn as_num(&self) -> Option<&Num> {
        match self {
            Json::Num(n) => Some(n),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The integer this value denotes, if it is a number written with no
    /// fraction or exponent part (Section 3.2).
    pub(crate) fn as_int(&self) -> Option<i128> {
        self.as_num().and_then(Num::as_int)
    }

    /// True if any number anywhere in this value is not admissible.
    pub(crate) fn has_inadmissible_number(&self) -> bool {
        match self {
            Json::Num(n) => !n.admissible(),
            Json::Arr(items) => items.iter().any(Json::has_inadmissible_number),
            Json::Obj(o) => o.iter().any(|(_, v)| v.has_inadmissible_number()),
            _ => false,
        }
    }

    /// Value equality per Section 3.4: identical JCS serializations. Members
    /// compare without regard to order and numbers compare as the doubles JCS
    /// writes. Both sides must come from text with no repeated member name.
    pub(crate) fn jcs_eq<'a>(&'a self, other: &'a Json) -> bool {
        match (self, other) {
            (Json::Null, Json::Null) => true,
            (Json::Bool(a), Json::Bool(b)) => a == b,
            (Json::Num(a), Json::Num(b)) => a.value == b.value,
            (Json::Str(a), Json::Str(b)) => a == b,
            (Json::Arr(a), Json::Arr(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.jcs_eq(y))
            }
            (Json::Obj(a), Json::Obj(b)) => {
                // Sorted once, so a wide object costs n log n and not n^2.
                let sorted = |object: &'a Obj| {
                    let mut members: Vec<(&'a str, &'a Json)> = object.iter().collect();
                    members.sort_unstable_by_key(|(name, _)| *name);
                    members
                };
                a.len() == b.len()
                    && sorted(a)
                        .into_iter()
                        .zip(sorted(b))
                        .all(|((k, v), (l, w))| k == l && v.jcs_eq(w))
            }
            _ => false,
        }
    }
}

/// A JSON object, members in document order.
#[derive(Debug, Clone, Default)]
pub(crate) struct Obj(Vec<(String, Json)>);

impl Obj {
    /// The value of member `name`. Where a name repeats the last one is
    /// returned; every caller but the unverified `jti` extraction of step 2c
    /// has already rejected such text.
    pub(crate) fn get(&self, name: &str) -> Option<&Json> {
        self.0.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &Json)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A JSON number, kept as written.
#[derive(Debug, Clone)]
pub(crate) struct Num {
    text: String,
    value: f64,
}

impl Num {
    fn new(text: &str) -> Self {
        // The grammar is checked by the reader. Rust rounds correctly and
        // returns an infinity beyond the double range.
        let value = text.parse::<f64>().unwrap_or(f64::NAN);
        Self {
            text: text.to_owned(),
            value,
        }
    }

    /// The double JCS serializes this number as.
    pub(crate) fn value(&self) -> f64 {
        self.value
    }

    /// The integer, if the number has no fraction or exponent part. An integer
    /// beyond `i128` saturates: such a value only ever meets a bounds check,
    /// which it fails the same way.
    pub(crate) fn as_int(&self) -> Option<i128> {
        if self.text.contains(['.', 'e', 'E']) {
            return None;
        }
        Some(self.text.parse::<i128>().unwrap_or({
            if self.text.starts_with('-') {
                i128::MIN
            } else {
                i128::MAX
            }
        }))
    }

    /// Section 3.4: admissible when the JCS serialization of this number's
    /// double denotes the same mathematical value as the text. Having an exact
    /// double is not the test: 2^60 has one, but JCS writes it as
    /// 1152921504606847000.
    pub(crate) fn admissible(&self) -> bool {
        self.value.is_finite() && decimal_digits(&self.text) == jcs_digits(self.value)
    }
}

/// A decimal literal as (significant digits, exponent), meaning
/// `0.DIGITS x 10^exponent`, with zero as `("", 0)`. Two literals denote the
/// same magnitude exactly when these are equal. The sign is not part of it: a
/// literal and its double always agree on the sign of a non-zero value.
fn decimal_digits(text: &str) -> (String, i64) {
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((m, e)) => (m, parse_exponent(e)),
        None => (unsigned, 0),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all: String = [int, frac].concat();
    let leading = all.len() - all.trim_start_matches('0').len();
    let digits = all.trim_matches('0');
    if digits.is_empty() {
        return (String::new(), 0);
    }
    let point = int.len() as i64 - leading as i64;
    (digits.to_owned(), point.saturating_add(exponent))
}

/// An exponent too long for `i64` saturates far outside the double range, so
/// it never equals the exponent of a finite double.
/// The digits ECMAScript's `Number::toString` writes for a finite double, and
/// so the digits JCS writes (RFC 8785 Section 3.2.2.3), in the form
/// [`decimal_digits`] returns. Layout is not part of it.
///
/// `{:e}` prints the shortest digit string that reads back as the same double,
/// as ECMAScript does. The two part ways in one case: the double lies exactly
/// halfway between two strings of that length and both read back as it. `{:e}`
/// then takes the upper string and ECMAScript the one whose last digit is
/// even.
fn jcs_digits(value: f64) -> (String, i64) {
    let magnitude = value.abs();
    let (digits, exponent) = decimal_digits(&format!("{magnitude:e}"));
    // The lower string differs from the upper in its last digit alone, and is
    // the even one only when the upper ends in an odd digit. One ending in 0
    // would be a shorter string, and `{:e}` would have printed that.
    let Some(last @ (b'3' | b'5' | b'7' | b'9')) = digits.bytes().last() else {
        return (digits, exponent);
    };
    let lower = format!("{}{}", &digits[..digits.len() - 1], char::from(last - 1));
    let halfway = format!("{lower}5");
    let scale = exponent.saturating_sub(halfway.len() as i64);
    if is_exactly(magnitude, &halfway, scale)
        && format!("0.{lower}e{exponent}").parse::<f64>() == Ok(magnitude)
    {
        return (lower, exponent);
    }
    (digits, exponent)
}

/// True if the positive finite double `value` is exactly `digits x 10^scale`,
/// for a digit string that ends in 5. Integer arithmetic only.
fn is_exactly(value: f64, digits: &str, scale: i64) -> bool {
    let Ok(n) = digits.parse::<u128>() else {
        return false;
    };
    // value = odd x 2^binary, which a double has exactly one way to be.
    let bits = value.to_bits();
    let fraction = bits & ((1 << 52) - 1);
    let biased = ((bits >> 52) & 0x7ff) as i64;
    let (mantissa, binary) = if biased == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1 << 52), biased - 1075)
    };
    if mantissa == 0 {
        return false;
    }
    let shift = mantissa.trailing_zeros();
    let (odd, binary) = (u128::from(mantissa >> shift), binary + i64::from(shift));
    // digits x 10^scale = (digits x 5^scale) x 2^scale, and `digits` is odd, so
    // the two forms are equal only part for part.
    let Some(five) = u32::try_from(scale.unsigned_abs())
        .ok()
        .and_then(|power| 5u128.checked_pow(power))
    else {
        return false;
    };
    if binary != scale {
        return false;
    }
    if scale >= 0 {
        n.checked_mul(five) == Some(odd)
    } else {
        n % five == 0 && n / five == odd
    }
}

fn parse_exponent(e: &str) -> i64 {
    e.parse::<i64>().unwrap_or({
        if e.starts_with('-') {
            i64::MIN / 2
        } else {
            i64::MAX / 2
        }
    })
}

/// Result of [`parse`].
pub(crate) struct Parsed {
    pub(crate) value: Json,
    /// Some object in the text repeats a member name.
    pub(crate) duplicate: bool,
}

/// Parse one JSON text (RFC 8259). Rejects trailing data, lone surrogate
/// escapes, a byte order mark and nesting past the reader's limit. A repeated
/// member name is reported, not rejected, because step 2c reads `jti` from
/// text that step 3b or 4b rejects only after the signature verifies.
pub(crate) fn parse(text: &str) -> Option<Parsed> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        text,
        pos: 0,
        duplicate: false,
    };
    reader.skip_ws();
    let value = reader.value(0)?;
    reader.skip_ws();
    (reader.pos == reader.bytes.len()).then_some(Parsed {
        value,
        duplicate: reader.duplicate,
    })
}

/// [`parse`], refusing a repeated member name.
pub(crate) fn parse_unique(text: &str) -> Option<Json> {
    parse(text).filter(|p| !p.duplicate).map(|p| p.value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
    duplicate: bool,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        (self.peek() == Some(byte)).then(|| self.pos += 1)
    }

    fn literal(&mut self, word: &str, value: Json) -> Option<Json> {
        self.bytes[self.pos..]
            .starts_with(word.as_bytes())
            .then(|| {
                self.pos += word.len();
                value
            })
    }

    fn value(&mut self, depth: usize) -> Option<Json> {
        match self.peek()? {
            b'n' => self.literal("null", Json::Null),
            b't' => self.literal("true", Json::Bool(true)),
            b'f' => self.literal("false", Json::Bool(false)),
            b'"' => self.string().map(Json::Str),
            b'[' => self.array(depth + 1),
            b'{' => self.object(depth + 1),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn array(&mut self, depth: usize) -> Option<Json> {
        if depth > MAX_NESTING {
            return None;
        }
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.eat(b']').is_some() {
            return Some(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(Json::Arr(items));
                }
                _ => return None,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<Json> {
        if depth > MAX_NESTING {
            return None;
        }
        self.eat(b'{')?;
        let mut members: Vec<(String, Json)> = Vec::new();
        self.skip_ws();
        if self.eat(b'}').is_some() {
            return Some(Json::Obj(Obj(members)));
        }
        loop {
            self.skip_ws();
            let name = self.string()?;
            self.skip_ws();
            self.eat(b':')?;
            self.skip_ws();
            let value = self.value(depth)?;
            members.push((name, value));
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }
        let mut seen = HashSet::with_capacity(members.len());
        if !members.iter().all(|(name, _)| seen.insert(name.as_str())) {
            self.duplicate = true;
        }
        Some(Json::Obj(Obj(members)))
    }

    fn number(&mut self) -> Option<Json> {
        let start = self.pos;
        let _ = self.eat(b'-');
        match self.peek()? {
            b'0' => self.pos += 1,
            b'1'..=b'9' => self.digits(),
            _ => return None,
        }
        if self.eat(b'.').is_some() {
            self.one_or_more_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.one_or_more_digits()?;
        }
        Some(Json::Num(Num::new(&self.text[start..self.pos])))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn one_or_more_digits(&mut self) -> Option<()> {
        let start = self.pos;
        self.digits();
        (self.pos > start).then_some(())
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = String::new();
        let mut run = self.pos;
        loop {
            match self.peek()? {
                b'"' => {
                    out.push_str(&self.text[run..self.pos]);
                    self.pos += 1;
                    return Some(out);
                }
                b'\\' => {
                    out.push_str(&self.text[run..self.pos]);
                    self.pos += 1;
                    out.push(self.escape()?);
                    run = self.pos;
                }
                0x00..=0x1f => return None,
                // Any other byte is part of a character of the input `str`,
                // which is valid UTF-8; `"` and `\` never occur inside one.
                _ => self.pos += 1,
            }
        }
    }

    fn escape(&mut self) -> Option<char> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let unit = self.hex4()?;
                let code = match unit {
                    0xD800..=0xDBFF => {
                        self.eat(b'\\')?;
                        self.eat(b'u')?;
                        let low = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&low) {
                            return None;
                        }
                        0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                    }
                    0xDC00..=0xDFFF => return None,
                    _ => unit,
                };
                char::from_u32(code)?
            }
            _ => return None,
        })
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.bytes.get(self.pos..self.pos + 4)?;
        let mut unit = 0u32;
        for d in digits {
            unit = (unit << 4) | (*d as char).to_digit(16)?;
        }
        self.pos += 4;
        Some(unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(text: &str) -> Num {
        match parse(text).expect("number").value {
            Json::Num(n) => n,
            other => panic!("not a number: {other:?}"),
        }
    }

    #[test]
    fn section_3_4_examples() {
        for text in ["0.1", "1e20", "9007199254740994", "1152921504606847000"] {
            assert!(num(text).admissible(), "{text}");
        }
        for text in [
            "9007199254740993",
            "1.00000000000000001",
            "1152921504606846976",
            "1e400",
            "1e-400",
        ] {
            assert!(!num(text).admissible(), "{text}");
        }
    }

    /// RFC 8785 Appendix B: each double and the text JCS writes for it.
    #[test]
    fn rfc_8785_sample_numbers_are_admissible() {
        for (bits, text) in [
            (0x0000000000000001u64, "5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
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
            let n = num(text);
            assert_eq!(n.value().to_bits(), bits, "{text}");
            assert!(n.admissible(), "{text}");
        }
    }

    /// A double exactly halfway between two shortest spellings is written
    /// with the even last digit. The other spelling reads back as the same
    /// double and is not admissible.
    #[test]
    fn a_tie_between_two_spellings_goes_to_the_even_digit() {
        for (written, other) in [
            // 2^-25 = 2.98023223876953125e-8
            ("2.9802322387695312e-8", "2.9802322387695313e-8"),
            // 1424953923781206.25
            ("1424953923781206.2", "1424953923781206.3"),
            // 2^50 + 0.25 = 1125899906842624.25
            ("1125899906842624.2", "1125899906842624.3"),
        ] {
            assert_eq!(num(written).value(), num(other).value(), "{written}");
            assert!(num(written).admissible(), "{written}");
            assert!(!num(other).admissible(), "{other}");
        }
        // A value that ends in 5 and is its own shortest spelling is no tie.
        for text in ["0.5", "2.5", "1.5", "35"] {
            assert!(num(text).admissible(), "{text}");
        }
    }

    #[test]
    fn equal_length_objects_with_different_names_are_not_equal() {
        let json = |text: &str| parse_unique(text).expect(text);
        assert!(!json(r#"{"a":1,"b":2}"#).jcs_eq(&json(r#"{"a":1,"c":2}"#)));
        assert!(!json(r#"{"a":1,"b":2}"#).jcs_eq(&json(r#"{"b":1,"a":2}"#)));
        assert!(json(r#"{"b":2,"a":1}"#).jcs_eq(&json(r#"{"a":1.0,"b":2e0}"#)));
    }

    #[test]
    fn admissible_spellings_of_one_value() {
        for text in [
            "1",
            "1.0",
            "1e0",
            "10e-1",
            "0.1E1",
            "-0",
            "0e999999999999999999999",
        ] {
            assert!(num(text).admissible(), "{text}");
        }
        assert_eq!(num("1").value(), num("1.0").value());
        assert_eq!(num("-0").value(), num("0").value());
    }

    #[test]
    fn integers_are_numbers_without_fraction_or_exponent() {
        assert_eq!(num("0").as_int(), Some(0));
        assert_eq!(num("-0").as_int(), Some(0));
        assert_eq!(num("1704067500").as_int(), Some(1_704_067_500));
        assert_eq!(num("1.0").as_int(), None);
        assert_eq!(num("1e0").as_int(), None);
        let huge = "9".repeat(60);
        assert_eq!(num(&huge).as_int(), Some(i128::MAX));
        assert_eq!(num(&format!("-{huge}")).as_int(), Some(i128::MIN));
    }

    #[test]
    fn rejects_what_rfc_8259_rejects() {
        for text in [
            "",
            " ",
            "01",
            "1.",
            ".5",
            "+1",
            "1e",
            "-",
            "NaN",
            "Infinity",
            "tru",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "'a'",
            "\"\t\"",
            "\"\\x\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "\"\\ud800\\u0041\"",
            "1 2",
            "\u{feff}1",
            "[",
            "{\"a\"}",
        ] {
            assert!(parse(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn agrees_with_serde_json_on_accepted_text() {
        for text in [
            "null",
            " [ 1 , 2.5e3 , \"a\\n\\u00e9\\ud83d\\ude00\" , { \"k\" : [ ] } ] ",
            "{\"a\":{\"b\":[true,false,null]},\"c\":\"\\\"\\\\\\/\"}",
            "\"é😀\"",
        ] {
            let ours = parse(text).expect(text).value;
            let theirs: serde_json::Value = serde_json::from_str(text).expect(text);
            assert!(same(&ours, &theirs), "{text}");
        }
    }

    fn same(ours: &Json, theirs: &serde_json::Value) -> bool {
        use serde_json::Value as V;
        match (ours, theirs) {
            (Json::Null, V::Null) => true,
            (Json::Bool(a), V::Bool(b)) => a == b,
            (Json::Num(a), V::Number(b)) => b.as_f64() == Some(a.value()),
            (Json::Str(a), V::String(b)) => a == b,
            (Json::Arr(a), V::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y))
            }
            (Json::Obj(a), V::Object(b)) => {
                a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|w| same(v, w)))
            }
            _ => false,
        }
    }

    #[test]
    fn reports_a_repeated_member_at_any_depth() {
        assert!(!parse("{\"a\":1,\"b\":{\"a\":2}}").unwrap().duplicate);
        assert!(parse("{\"a\":1,\"a\":2}").unwrap().duplicate);
        assert!(parse("[{\"x\":{\"a\":1,\"a\":1}}]").unwrap().duplicate);
        assert!(parse("{\"a\":1,\"\\u0061\":2}").unwrap().duplicate);
        assert!(parse_unique("{\"a\":1,\"a\":2}").is_none());
        let last = parse("{\"jti\":\"x\",\"jti\":\"y\"}").unwrap().value;
        assert_eq!(
            last.as_obj().unwrap().get("jti").unwrap().as_str(),
            Some("y")
        );
    }

    #[test]
    fn equality_ignores_member_order_and_number_spelling() {
        let a = parse_unique("{\"a\":[1,2.0],\"b\":null}").unwrap();
        let b = parse_unique("{\"b\":null,\"a\":[1.0,2]}").unwrap();
        let c = parse_unique("{\"b\":null,\"a\":[2,1]}").unwrap();
        assert!(a.jcs_eq(&b));
        assert!(!a.jcs_eq(&c));
    }

    #[test]
    fn nesting_limit() {
        let ok = format!("{}{}", "[".repeat(MAX_NESTING), "]".repeat(MAX_NESTING));
        let deep = format!(
            "{}{}",
            "[".repeat(MAX_NESTING + 1),
            "]".repeat(MAX_NESTING + 1)
        );
        assert!(parse(&ok).is_some());
        assert!(parse(&deep).is_none());
    }
}
