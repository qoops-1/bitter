use std::{borrow::Cow, fmt, error::Error, str};

// Kindly stolen from `urlencoding` crate
pub fn urlencode(mut data: &[u8]) -> String {
    let mut result = String::new();
    loop {
        // Fast path to skip over safe chars at the beginning of the remaining string
        let ascii_len = data.iter()
            .take_while(|c| matches!(c, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' |  b'-' | b'.' | b'_' | b'~')).count();

        let (safe, rest) = if ascii_len >= data.len() {
            (data, &[][..]) // redundant to optimize out a panic in split_at
        } else {
            data.split_at(ascii_len)
        };
        if !safe.is_empty() {
            result.push_str(unsafe { str::from_utf8_unchecked(safe) });
        }
        if rest.is_empty() {
            break;
        }

        match rest.split_first() {
            Some((byte, rest)) => {
                let hex = format!("%{:02X}", byte);
                result.push_str(&hex);
                data = rest;
            }
            None => break,
        };
    }
    result
}


#[derive(Debug)]
pub struct BitterMistake(Cow<'static, str>);

impl BitterMistake {
    pub fn new(msg: &'static str) -> BitterMistake {
        BitterMistake(Cow::Borrowed(msg))
    }

    pub fn new_owned(msg: String) -> BitterMistake {
        BitterMistake(Cow::Owned(msg))
    }

    pub fn new_err<T: Error>(err: T) -> BitterMistake {
        Self(Cow::Owned(err.to_string()))
    }
}

impl fmt::Display for BitterMistake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for BitterMistake {}

pub type BitterResult<T> = Result<T, BitterMistake>;