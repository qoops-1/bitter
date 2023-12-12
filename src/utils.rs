use std::{
    borrow::Cow,
    error::Error,
    fmt,
    ops::{Add, Div, Sub},
    str,
};

#[inline]
pub fn roundup_div<T>(a: T, b: T) -> T
where
    T: Add<Output = T> + Sub<Output = T> + Div<Output = T> + From<u8> + Copy,
{
    let one: T = Into::into(1u8);
    (a + b - one) / b
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
