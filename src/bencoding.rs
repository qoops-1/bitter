use std::{
    collections::HashMap,
    io::{Cursor, Seek, SeekFrom},
    str::from_utf8,
};
use crate::utils::{BitterMistake, BitterResult};

#[derive(Debug, PartialEq, Eq)]
pub enum BencodedValue<'a> {
    BencodedInt(i64),
    BencodedStr(&'a [u8]),
    BencodedList(Vec<BencodedValue<'a>>),
    BencodedDict(BencodedDict<'a>),
}

impl<'a> BencodedValue <'a> {
    pub fn try_into_string(&self) -> BitterResult<&'a str> {
        self.try_into_bytestring()
            .and_then(|bytes| from_utf8(bytes).map_err(BitterMistake::new_err))
    }

    pub fn try_into_bytestring(&self) -> BitterResult<&'a [u8]> {
        match self {
            BencodedValue::BencodedStr(s) => Ok(s),
            _ => Err(BitterMistake::new("not a string")),
        }
    }

    pub fn try_into_dict(&self) -> BitterResult<&BencodedDict> {
        match self {
            BencodedValue::BencodedDict(d) => Ok(d),
            _ => Err(BitterMistake::new("not a dict")),
        }
    }

    pub fn try_into_int(&self) -> BitterResult<&i64> {
        match self {
            BencodedValue::BencodedInt(i) => Ok(i),
            _ => Err(BitterMistake::new("not an int")),
        }
    }

    pub fn try_into_list(&self) -> BitterResult<&Vec<BencodedValue>> {
        match self {
            BencodedValue::BencodedList(l) => Ok(l),
            _ => Err(BitterMistake::new("not a list")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BencodedDict<'a>(HashMap<&'a [u8], BencodedValue<'a>>);

impl<'a> BencodedDict<'a> {
    /// Returns next key
    pub fn get_key(&self, key: &'a str) -> Result<&BencodedValue, BitterMistake> {
        self.0
            .get(key.as_bytes())
            .ok_or(BitterMistake::new_owned(format!("key {key} not found")))
    }
}
pub trait BDecode: Sized {
    fn bdecode(s: &BencodedValue) -> BitterResult<Self>;
}

pub fn bdecode<T: BDecode>(s: &[u8]) -> BitterResult<T> {
    let mut c = Cursor::new(s);
    let bencoded = bdecode_any(&mut c)?;

    if c.get_ref().len() > c.position() as usize {
        return Err(BitterMistake::new("unparsed trailing data"));
    }
    T::bdecode(&bencoded)
}

// Some standard type implementations

pub fn bdecode_any<'a> (buf: &mut Cursor<&'a [u8]>) -> BitterResult<BencodedValue<'a>> {
    bdecode_int(buf)
        .map(BencodedValue::BencodedInt)
        .or_else(|_| bdecode_dict(buf).map(BencodedValue::BencodedDict))
        .or_else(|_| bdecode_list(buf).map(BencodedValue::BencodedList))
        .or_else(|_| bdecode_str(buf).map(BencodedValue::BencodedStr))
}

pub fn bdecode_int(buf: &mut Cursor<&[u8]>) -> BitterResult<i64> {
    if !first_char_matches(buf, b'i') {
        return Err(BitterMistake::new("not an int"));
    }
    let cur_pos = buf.stream_position().unwrap() as usize;
    let number_end = buf.get_ref()[cur_pos..]
        .iter()
        .position(|c| *c == b'e')
        .ok_or(BitterMistake::new("end of integer not found"))?
        + cur_pos;

    buf.seek(SeekFrom::Start(number_end as u64 + 1)).unwrap();

    String::from_utf8_lossy(&buf.get_ref()[cur_pos..number_end])
        .parse::<i64>()
        .map_err(BitterMistake::new_err)
}

pub fn bdecode_dict<'a>(buf: &mut Cursor<&'a [u8]>) -> BitterResult<BencodedDict<'a>> {
    if !first_char_matches(buf, b'd') {
        return Err(BitterMistake::new("not a dict"));
    }
    let mut map: HashMap<&'a [u8], BencodedValue> = HashMap::new();

    while buf.stream_position().unwrap() < buf.get_ref().len() as u64 {
        if first_char_matches(buf, b'e') {
            return Ok(BencodedDict(map));
        }
        let key = bdecode_str(buf)?;
        let value = bdecode_any(buf)?;
        if map.contains_key(&key) {
            return Err(BitterMistake::new("Duplicate key in dict"));
        }
        map.insert(key, value);
    }
    Err(BitterMistake::new("unterminated dict"))
}

pub fn bdecode_list<'a>(buf: &mut Cursor<&'a [u8]>) -> BitterResult<Vec<BencodedValue<'a>>> {
    if !first_char_matches(buf, b'l') {
        return Err(BitterMistake::new("not a list"));
    }

    let mut list = Vec::new();

    while buf.stream_position().unwrap() < buf.get_ref().len() as u64 {
        if first_char_matches(buf, b'e') {
            return Ok(list);
        }
        let item = bdecode_any(buf)?;
        list.push(item);
    }
    Err(BitterMistake::new("unterminated list"))
}

pub fn bdecode_str<'a>(buf: &mut Cursor<&'a [u8]>) -> BitterResult<&'a [u8]> {
    let cur_pos = buf.stream_position().unwrap() as usize;

    let len_end = buf.get_ref()[cur_pos..]
        .iter()
        .position(|c| *c == b':')
        .ok_or(BitterMistake::new("length prefix not found"))?
        + cur_pos;

    let strlen: usize = String::from_utf8_lossy(&buf.get_ref()[cur_pos..len_end])
        .parse()
        .map_err(BitterMistake::new_err)?;

    let str_end = len_end + strlen + 1;
    if buf.get_ref().len() < str_end {
        return Err(BitterMistake::new("string length too long"));
    }
    buf.seek(SeekFrom::Start(str_end as u64)).unwrap();
    Ok(&buf.get_ref()[len_end + 1..str_end])
}

fn first_char_matches(buf: &mut Cursor<&[u8]>, c: u8) -> bool {
    // Err is impossible for Cursor
    let cur_pos = buf.stream_position().unwrap() as usize;
    let have_match = cur_pos != buf.get_ref().len() && buf.get_ref()[cur_pos] == c;

    if have_match {
        // I don't care about int64 overflow
        buf.seek(SeekFrom::Current(1)).unwrap();
    }
    return have_match;
}

#[cfg(test)]
mod tests {

    fn assert_finished(c: &Cursor<&[u8]>) {
        assert_eq!(c.get_ref().len(), c.position() as usize);
    }

    use super::*;
    #[test]
    fn bdecode_int_test() {
        let mut c: Cursor<&[u8]> = Cursor::new(b"i0e");
        assert_eq!(0, bdecode_int(&mut c).unwrap());
        assert_finished(&c);

        c = Cursor::new(b"i-1e");
        assert_eq!(-1, bdecode_int(&mut c).unwrap());
        assert_finished(&c);

        c = Cursor::new(b"i342e");
        assert_eq!(342, bdecode_int(&mut c).unwrap());
        assert_finished(&c);
    }

    #[test]
    fn bdecode_int_error_test() {
        assert!(bdecode_int(&mut Cursor::new(b"ie")).is_err());
        assert!(bdecode_int(&mut Cursor::new(b"i342")).is_err());
        assert!(bdecode_int(&mut Cursor::new(b"342e")).is_err());
        assert!(bdecode_int(&mut Cursor::new(b"342")).is_err());
        assert!(bdecode_int(&mut Cursor::new(b"")).is_err());
    }

    #[test]
    fn bdecode_str_test() {
        let mut c: Cursor<&[u8]> = Cursor::new(b"5:hello");
        assert_eq!(b"hello", bdecode_str(&mut c).unwrap());
        assert_finished(&c);

        c = Cursor::new(b"0:");
        assert_eq!(b"", bdecode_str(&mut c).unwrap());
        assert_finished(&c);

        c = Cursor::new(b"13:hello:friends");
        assert_eq!(b"hello:friends", bdecode_str(&mut c).unwrap());
        assert_finished(&c);

        c = Cursor::new(b"1:1");
        assert_eq!(b"1", bdecode_str(&mut c).unwrap());
        assert_finished(&c);
    }

    #[test]
    fn bdecode_str_error_test() {
        assert!(bdecode_str(&mut Cursor::new(b"1:")).is_err());
        assert!(bdecode_str(&mut Cursor::new(b"5:hell")).is_err());
        assert!(bdecode_str(&mut Cursor::new(b"hello")).is_err());
        assert!(bdecode_str(&mut Cursor::new(b"")).is_err());
        assert!(bdecode_str(&mut Cursor::new(b":")).is_err());
        assert!(bdecode_str(&mut Cursor::new(b"hello:hello")).is_err());
    }

    #[test]
    fn bdecode_list_test() {
        use BencodedValue::*;
        let l1: &[u8] = b"l4:spam4:eggse";
        let l2: &[u8] = b"li342ei-1ee";

        let mut c = Cursor::new(l1);
        assert_eq!(
            bdecode_list(&mut c).unwrap(),
            vec![BencodedStr(b"spam"), BencodedStr(b"eggs")]
        );
        assert_finished(&c);

        c = Cursor::new(l2);
        assert_eq!(
            bdecode_list(&mut c).unwrap(),
            vec![BencodedInt(342), BencodedInt(-1)]
        );
        assert_finished(&c);

        c = Cursor::new(b"le");
        assert_eq!(bdecode_list(&mut c).unwrap(), vec![]);
        assert_finished(&c);

        let l_of_l = format!("l{}{}e", from_utf8(l1).unwrap(), from_utf8(l2).unwrap());
        c = Cursor::new(l_of_l.as_bytes());
        assert_eq!(
            bdecode_list(&mut c).unwrap(),
            vec![
                BencodedList(vec![BencodedStr(b"spam"), BencodedStr(b"eggs")]),
                BencodedList(vec![BencodedInt(342), BencodedInt(-1)])
            ]
        );
        assert_finished(&c);
    }

    #[test]
    fn bdecode_dict_test() {
        use BencodedValue as BVal;
        let d1: &[u8] = b"d3:cow3:moo4:spam4:eggse";
        let d2: &[u8] = b"d4:spaml1:a1:bee";

        let mut c = Cursor::new(d1);
        assert_eq!(
            bdecode_dict(&mut c).unwrap(),
            BencodedDict(HashMap::from([
                (b"cow" as &[u8], BVal::BencodedStr(b"moo")),
                (b"spam", BVal::BencodedStr(b"eggs"))
            ]))
        );
        assert_finished(&c);

        c = Cursor::new(d2);
        assert_eq!(
            bdecode_dict(&mut c).unwrap(),
            BencodedDict(HashMap::from([(
                b"spam" as &[u8],
                BVal::BencodedList(vec![BVal::BencodedStr(b"a"), BVal::BencodedStr(b"b")])
            )]))
        );
        assert_finished(&c);

        c = Cursor::new(b"de");
        assert_eq!(bdecode_dict(&mut c).unwrap(), BencodedDict(HashMap::new()));
        assert_finished(&c);
    }
}
