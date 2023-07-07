use std::{collections::HashMap, num::ParseIntError, io::{Cursor, SeekFrom, Seek}};

#[derive(Debug, PartialEq, Eq)]
pub enum BencodedValue {
    BencodedInt(i64),
    BencodedStr(String),
    BencodedList(Vec<BencodedValue>),
    BencodedDict(BencodedDict),
}

impl BencodedValue {
    pub fn try_into_string(self) -> Result<String, String> {
        match self {
            BencodedValue::BencodedStr(s) => Ok(s),
            _ => Err("not a string".to_owned()),
        }
    }

    pub fn try_into_dict(self) -> Result<BencodedDict, String> {
        match self {
            BencodedValue::BencodedDict(d) => Ok(d),
            _ => Err("not a dict".to_owned()),
        }
    }

    pub fn try_into_int(self) -> Result<i64, String> {
        match self {
            BencodedValue::BencodedInt(i) => Ok(i),
            _ => Err("not an int".to_owned()),
        }
    }

    pub fn try_into_list(self) -> Result<Vec<BencodedValue>, String> {
        match self {
            BencodedValue::BencodedList(l) => Ok(l),
            _ => Err("not a list".to_owned()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BencodedDict(HashMap<String, BencodedValue>);

impl BencodedDict {
    /// Returns next key 
    pub fn get_key(&self, key: &str) -> Result<&BencodedValue, String> {
        self.0.get(key).ok_or(format!("key {} not found", key))
    }
}
pub trait BDecode: Sized {
    fn bdecode(s: &BencodedValue) -> Result<Self, String>;
}

// Some standard type implementations

pub fn bdecode_any(s: &mut Cursor<&str>) -> Result<BencodedValue, String> {
    bdecode_int(s).map(BencodedValue::BencodedInt)
        .or(bdecode_dict(s).map(BencodedValue::BencodedDict))
        .or(bdecode_list(s).map(BencodedValue::BencodedList))
        .or(bdecode_str(s).map(BencodedValue::BencodedStr))
}

pub fn bdecode_int(s: &mut Cursor<&str>) -> Result<i64, String> {
    let ascii_bytes = s.get_ref().as_bytes();
    
    if !first_char_matches(s, b'i'){
        return Err("not an int".to_owned());
    }
    let cur_pos = s.stream_position().unwrap() as usize;
    let number_end = ascii_bytes[cur_pos..].iter().position(|c| *c == b'e').ok_or("end of integer not found")?;
    
    s.seek(SeekFrom::Current(number_end as i64)).map_err(|e| e.to_string())?;
    s.get_ref()[1..number_end]
        .parse()
        .map_err(|parse_err: ParseIntError| parse_err.to_string())
}

pub fn bdecode_dict(s: &mut Cursor<&str>) -> Result<BencodedDict, String> {
    if !first_char_matches(s, b'd') {
        return Err("not a dict".to_owned());
    }
    let mut map: HashMap<String, BencodedValue> = HashMap::new();

    while s.stream_position().unwrap() < s.get_ref().len() as u64 {
        let key = bdecode_str(s)?;
        let value = bdecode_any(s)?;
        if map.contains_key(&key) {
            return Err(format!("Duplicate key \"{}\" in dict", key));
        }
        map.insert(key, value);
    }
    Ok(BencodedDict(map))
}

pub fn bdecode_list(s: &mut Cursor<&str>) -> Result<Vec<BencodedValue>, String> {
    if !first_char_matches(s, b'l') {
        return Err("not a list".to_owned());
    }
    unimplemented!()
}

pub fn bdecode_str(s: &mut Cursor<&str>) -> Result<String, String> {
        let ascii_bytes = s.get_ref().as_bytes();
        let cur_pos = s.stream_position().map_err(|e| e.to_string())? as usize;
        
        let len_end = ascii_bytes[cur_pos..].iter().position(|c| *c == b':').ok_or("length prefix not found".to_owned())? + cur_pos;
        let strlen: usize = s.get_ref()[cur_pos..len_end]
            .parse()
            .map_err(|parse_err: ParseIntError| parse_err.to_string())?;

        let str_end = len_end + strlen + 1;
        if ascii_bytes.len() < str_end {
            return Err("string length too long".to_owned());
        }
        Ok(s.get_ref()[len_end + 1..str_end].to_owned())
}

fn first_char_matches(s: &mut Cursor<&str>, c: u8) -> bool {
    let ascii_bytes = s.get_ref().as_bytes();
    // Err is impossible for Cursor
    let cur_pos = s.stream_position().unwrap() as usize;

    // I don't care about int64 overflow
    s.seek(SeekFrom::Current(1)).unwrap();
    return cur_pos != ascii_bytes.len() && ascii_bytes[cur_pos] == c
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
        assert_eq!("hello:friends", bdecode_str(&mut Cursor::new("13:hello:friends")).unwrap());
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
