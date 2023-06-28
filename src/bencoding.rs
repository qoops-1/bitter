use std::num::ParseIntError;

pub trait BDecode: Sized {
    fn decode(s: &str) -> Result<Self, String>;
}

// Some standard type implementations

impl BDecode for i64 {
    fn decode(s: &str) -> Result<Self, String> {
        let ascii_bytes: &[u8] = s.as_bytes();
        if ascii_bytes[0] != b'i' {
            return Result::Err("not an integer".to_owned());
        }
        let number_end = s.find('e').ok_or("end of integer not found")?;
        s[1..number_end]
            .parse()
            .map_err(|parse_err: ParseIntError| parse_err.to_string())
    }
}

impl BDecode for String {
    fn decode(s: &str) -> Result<Self, String> {
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
    fn decode_u64() {
        assert_eq!(0, i64::decode("i0e").unwrap());
        assert_eq!(-1, i64::decode("i-1e").unwrap());
        assert_eq!(342, i64::decode("i342e").unwrap())
    }
}
