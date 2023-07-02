use std::{collections::HashMap, num::ParseIntError, io::{Cursor, SeekFrom, Seek}};

#[derive(Debug, PartialEq, Eq)]
pub enum BencodedValue {
    BencodedInt(i64),
    BencodedStr(String),
    BencodedList(Box<[BencodedValue]>),
    BencodedDict(HashMap<String, BencodedValue>),
}
pub trait BDecode: Sized {
    fn bdecode(s: &str) -> Result<Self, String>;
}

// Some standard type implementations

pub fn bdecode_any(s: &mut Cursor<&str>) -> Result<BencodedValue, String> {
    bdecode_int(s)
        .or(bdecode_str(s))
        .or(bdecode_dict(s))
        .or(bdecode_list(s))
}

pub fn bdecode_int(s: &mut Cursor<&str>) -> Result<BencodedValue, String> {
    let ascii_bytes = s.get_ref().as_bytes();
    let cur_pos = s.stream_position().map_err(|e| e.to_string())? as usize;
    if cur_pos == ascii_bytes.len() || ascii_bytes[cur_pos] != b'i' {
        return Result::Err("not an integer".to_owned());
    }
    let number_end = ascii_bytes[cur_pos..].iter().position(|c| *c == b'e').ok_or("end of integer not found")?;
    
    s.seek(SeekFrom::Current(number_end as i64)).map_err(|e| e.to_string())?;
    s.get_ref()[1..number_end]
        .parse()
        .map_err(|parse_err: ParseIntError| parse_err.to_string())
        .map(BencodedValue::BencodedInt)
}

pub fn bdecode_dict(s: &mut Cursor<&str>) -> Result<BencodedValue, String> {
    let ascii_bytes = s.get_ref().as_bytes();
    let cur_pos = s.stream_position().map_err(|e| e.to_string())? as usize;
    if cur_pos == ascii_bytes.len() || ascii_bytes[cur_pos] != b'd' {
        return Result::Err("not a dict".to_owned());
    }
    s.seek(SeekFrom::Current(1));
    bdecode_any(s);
    unimplemented!();
}

pub fn bdecode_list(s: &mut Cursor<&str>) -> Result<BencodedValue, String> {
    unimplemented!()
}

pub fn bdecode_str(s: &mut Cursor<&str>) -> Result<BencodedValue, String> {
        let ascii_bytes = s.get_ref().as_bytes();
        let cur_pos = s.stream_position().map_err(|e| e.to_string())? as usize;
        
        let len_end = ascii_bytes[cur_pos..].iter().position(|c| *c == b':').ok_or("length prefix not found".to_owned())? + cur_pos;
        let strlen: usize = s.get_ref()[cur_pos..len_end]
            .parse()
            .map_err(|parse_err: ParseIntError| parse_err.to_string())?;

        let str_end = len_end + strlen + 1;
        if ascii_bytes.len() < str_end {
            return Result::Err("string length too long".to_owned());
        }
        Result::Ok(BencodedValue::BencodedStr(s.get_ref()[len_end + 1..str_end].to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bdecode_int_test() {
        assert_eq!(BencodedValue::BencodedInt(0), bdecode_int(&mut Cursor::new("i0e")).unwrap());
        assert_eq!(BencodedValue::BencodedInt(-1), bdecode_int(&mut Cursor::new("i-1e")).unwrap());
        assert_eq!(BencodedValue::BencodedInt(342), bdecode_int(&mut Cursor::new("i342e")).unwrap())
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
        assert_eq!(BencodedValue::BencodedStr("hello".to_owned()), bdecode_str(&mut Cursor::new("5:hello")).unwrap());
        assert_eq!(BencodedValue::BencodedStr(String::new()), bdecode_str(&mut Cursor::new("0:")).unwrap());
        assert_eq!(BencodedValue::BencodedStr("hello:friends".to_owned()), bdecode_str(&mut Cursor::new("13:hello:friends")).unwrap());
        assert_eq!(BencodedValue::BencodedStr("1".to_owned()), bdecode_str(&mut Cursor::new("1:1")).unwrap());
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
