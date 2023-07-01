use std::{collections::HashMap, num::ParseIntError, str::FromStr};

enum BencodedValue {
    BencodedInt(i64),
    BencodedStr(String),
    BencodedList(Box<[BencodedValue]>),
    BencodedDict(HashMap<String, BencodedValue>),
}
pub trait BDecode: Sized {
    fn bdecode(s: &str) -> Result<Self, String>;
}

// Some standard type implementations

fn bdecode_int<T: FromStr<Err = ParseIntError>>(s: &str) -> Result<T, String> {
    let ascii_bytes: &[u8] = s.as_bytes();
    if ascii_bytes.len() == 0 || ascii_bytes[0] != b'i' {
        return Result::Err("not an integer".to_owned());
    }
    let number_end = s.find('e').ok_or("end of integer not found")?;
    s[1..number_end]
        .parse()
        .map_err(|parse_err: ParseIntError| parse_err.to_string())
}

fn bdecode_dict(s: &str) -> Result<BencodedValue, String> {
    let ascii_bytes: &[u8] = s.as_bytes();
    if ascii_bytes.len() == 0 || ascii_bytes[0] != b'd' {
        return Result::Err("not a dict".to_owned());
    }
    BencodedValue::bdecode(&s[1..])
}

impl BDecode for BencodedValue {
    fn bdecode(s: &str) -> Result<Self, String> {}
}
impl BDecode for u64 {
    fn bdecode(s: &str) -> Result<Self, String> {
        bdecode_int(s)
    }
}

impl BDecode for String {
    fn bdecode(s: &str) -> Result<Self, String> {
        let len_end = s.find(':').ok_or("length prefix not found".to_owned())?;
        let strlen: usize = s[..len_end]
            .parse()
            .map_err(|parse_err: ParseIntError| parse_err.to_string())?;

        Result::Ok(s[len_end + 1..len_end + strlen + 1].to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bdecode_i64() {
        assert_eq!(0, i64::bdecode("i0e").unwrap());
        assert_eq!(-1, i64::bdecode("i-1e").unwrap());
        assert_eq!(342, i64::bdecode("i342e").unwrap())
    }

    #[test]
    fn bdecode_i64_error() {
        assert!(i64::bdecode("ie").is_err());
        assert!(i64::bdecode("i342").is_err());
        assert!(i64::bdecode("342e").is_err());
        assert!(i64::bdecode("342").is_err());
        assert!(i64::bdecode("").is_err());
    }
}
