use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    fmt,
    fmt::Display,
    io::{Cursor, Seek, SeekFrom},
    num::ParseIntError,
};

#[derive(Debug)]
pub struct ParsingError<'a>(Cow<'a, str>);

impl<'a> ParsingError<'a> {
    pub fn new(msg: &str) -> ParsingError {
        ParsingError(Cow::Borrowed(msg))
    }

    pub fn new_owned(msg: String) -> ParsingError<'a> {
        ParsingError(Cow::Owned(msg))
    }
}

impl<'a> Display for ParsingError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'a> Error for ParsingError<'a> {}

pub type ParsingResult<'a, T> = Result<T, ParsingError<'a>>;

#[derive(Debug, PartialEq, Eq)]
pub enum BencodedValue<'a> {
    BencodedInt(i64),
    BencodedStr(&'a str),
    BencodedList(Vec<BencodedValue<'a>>),
    BencodedDict(BencodedDict<'a>),
}

impl<'a> BencodedValue<'a> {
    pub fn try_into_string(self) -> Result<&'a str, ParsingError<'a>> {
        match self {
            BencodedValue::BencodedStr(s) => Ok(s),
            _ => Err(ParsingError::new("not a string")),
        }
    }

    pub fn try_into_dict(self) -> ParsingResult<'a, BencodedDict<'a>> {
        match self {
            BencodedValue::BencodedDict(d) => Ok(d),
            _ => Err(ParsingError::new("not a dict")),
        }
    }

    pub fn try_into_int(self) -> Result<i64, ParsingError<'a>> {
        match self {
            BencodedValue::BencodedInt(i) => Ok(i),
            _ => Err(ParsingError::new("not an int")),
        }
    }

    pub fn try_into_list(self) -> Result<Vec<BencodedValue<'a>>, ParsingError<'a>> {
        match self {
            BencodedValue::BencodedList(l) => Ok(l),
            _ => Err(ParsingError::new("not a list")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BencodedDict<'a>(HashMap<&'a str, BencodedValue<'a>>);

impl<'a> BencodedDict<'a> {
    /// Returns next key
    pub fn get_key(&self, key: &'a str) -> Result<&BencodedValue, ParsingError> {
        self.0
            .get(key)
            .ok_or(ParsingError::new_owned(format!("key \"{key}\" not found")))
    }
}
pub trait BDecode: Sized {
    fn bdecode<'a>(s: &BencodedValue<'a>) -> ParsingResult<'a, Self>;
}

// Some standard type implementations

pub fn bdecode_any<'a>(s: &mut Cursor<&'a str>) -> ParsingResult<'a, BencodedValue<'a>> {
    bdecode_int(s)
        .map(BencodedValue::BencodedInt)
        .or(bdecode_dict(s).map(BencodedValue::BencodedDict))
        .or(bdecode_list(s).map(BencodedValue::BencodedList))
        .or(bdecode_str(s).map(BencodedValue::BencodedStr))
}

pub fn bdecode_int<'a>(s: &mut Cursor<&'a str>) -> ParsingResult<'a, i64> {
    let ascii_bytes = s.get_ref().as_bytes();

    if !first_char_matches(s, b'i') {
        return Err(ParsingError::new("not an int"));
    }
    let cur_pos = s.stream_position().unwrap() as usize;
    let number_end = ascii_bytes[cur_pos..]
        .iter()
        .position(|c| *c == b'e')
        .ok_or(ParsingError::new("end of integer not found"))?;

    s.seek(SeekFrom::Current(number_end as i64))
        .map_err(|e| ParsingError::new_owned(e.to_string()))?;
    s.get_ref()[1..number_end]
        .parse::<i64>()
        .map_err(|e| ParsingError::new_owned(e.to_string()))
}

pub fn bdecode_dict<'a>(s: &mut Cursor<&'a str>) -> ParsingResult<'a, BencodedDict<'a>> {
    if !first_char_matches(s, b'd') {
        return Err(ParsingError::new("not a dict"));
    }
    let mut map: HashMap<&'a str, BencodedValue> = HashMap::new();

    while s.stream_position().unwrap() < s.get_ref().len() as u64 {
        if first_char_matches(s, b'e') {
            return Ok(BencodedDict(map));
        }
        let key = bdecode_str(s)?;
        let value = bdecode_any(s)?;
        if map.contains_key(&key) {
            return Err(ParsingError::new_owned(format!(
                "Duplicate key \"{key}\" in dict"
            )));
        }
        map.insert(key, value);
    }
    Err(ParsingError::new("unterminated dict"))
}

pub fn bdecode_list<'a>(s: &mut Cursor<&'a str>) -> ParsingResult<'a, Vec<BencodedValue<'a>>> {
    if !first_char_matches(s, b'l') {
        return Err(ParsingError::new("not a list"));
    }

    let mut list = Vec::new();

    while s.stream_position().unwrap() < s.get_ref().len() as u64 {
        if first_char_matches(s, b'e') {
            return Ok(list);
        }
        let item = bdecode_any(s)?;
        list.push(item);
    }
    Err(ParsingError::new("unterminated dict"))
}

pub fn bdecode_str<'a>(s: &mut Cursor<&'a str>) -> ParsingResult<'a, &'a str> {
    let ascii_bytes = s.get_ref().as_bytes();
    let cur_pos = s
        .stream_position()
        .map_err(|e| ParsingError::new_owned(e.to_string()))? as usize;

    let len_end = ascii_bytes[cur_pos..]
        .iter()
        .position(|c| *c == b':')
        .ok_or(ParsingError::new("length prefix not found"))?
        + cur_pos;
    let strlen: usize = s.get_ref()[cur_pos..len_end]
        .parse()
        .map_err(|parse_err: ParseIntError| ParsingError::new_owned(parse_err.to_string()))?;

    let str_end = len_end + strlen + 1;
    if ascii_bytes.len() < str_end {
        return Err(ParsingError::new("string length too long"));
    }
    Ok(&s.get_ref()[len_end + 1..str_end])
}

fn first_char_matches(s: &mut Cursor<&str>, c: u8) -> bool {
    let ascii_bytes = s.get_ref().as_bytes();
    // Err is impossible for Cursor
    let cur_pos = s.stream_position().unwrap() as usize;

    // I don't care about int64 overflow
    s.seek(SeekFrom::Current(1)).unwrap();
    return cur_pos != ascii_bytes.len() && ascii_bytes[cur_pos] == c;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bdecode_int_test() {
        assert_eq!(0, bdecode_int(&mut Cursor::new("i0e")).unwrap());
        assert_eq!(-1, bdecode_int(&mut Cursor::new("i-1e")).unwrap());
        assert_eq!(342, bdecode_int(&mut Cursor::new("i342e")).unwrap())
    }

    #[test]
    fn bdecode_int_error_test() {
        assert!(bdecode_int(&mut Cursor::new("ie")).is_err());
        assert!(bdecode_int(&mut Cursor::new("i342")).is_err());
        assert!(bdecode_int(&mut Cursor::new("342e")).is_err());
        assert!(bdecode_int(&mut Cursor::new("342")).is_err());
        assert!(bdecode_int(&mut Cursor::new("")).is_err());
    }

    #[test]
    fn bdecode_str_test() {
        assert_eq!("hello", bdecode_str(&mut Cursor::new("5:hello")).unwrap());
        assert_eq!(String::new(), bdecode_str(&mut Cursor::new("0:")).unwrap());
        assert_eq!(
            "hello:friends",
            bdecode_str(&mut Cursor::new("13:hello:friends")).unwrap()
        );
        assert_eq!("1", bdecode_str(&mut Cursor::new("1:1")).unwrap());
    }

    #[test]
    fn bdecode_str_error_test() {
        assert!(bdecode_str(&mut Cursor::new("1:")).is_err());
        assert!(bdecode_str(&mut Cursor::new("5:hell")).is_err());
        assert!(bdecode_str(&mut Cursor::new("hello")).is_err());
        assert!(bdecode_str(&mut Cursor::new("")).is_err());
        assert!(bdecode_str(&mut Cursor::new(":")).is_err());
        assert!(bdecode_str(&mut Cursor::new("hello:hello")).is_err());
    }
}
