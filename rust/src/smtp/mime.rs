extern crate mime;
use nom::character::streaming::crlf;
use nom::character::{is_alphanumeric, is_space};
use nom::bytes::complete::take_while;

pub struct MIMEHeader {
    key: String,
    value: String,
}

pub struct SMTPMIME {
    headers: Vec<MIMEHeader>,
    body_begin: bool,
    body_end: bool,
}

#[inline]
fn is_valid_string(b: u8) -> bool {
    is_alphanumeric(b)
}

named!(#[inline], parse_data<&[u8], &str>,
    map_res!(take_while!(is_valid_string), std::str::from_utf8)
);

named!(
    hcolon<char>,
    delimited!(take_while!(is_space), char!(':'), take_while!(is_space))
);

named!(
    parse_mime_header<MIMEHeader>,
    do_parse!(
        n: parse_data
            >> hcolon
            >> v: parse_data
            >> crlf
            >> (MIMEHeader {
                key: String::from(n),
                value: String::from(v)
            })
    )
);

named!(
    parse_full_msg<SMTPMIME>,
    do_parse!(
        
        )
    );

#[cfg(test)]
mod test {
    use crate::smtp::mime::*;

    #[test]
    fn test_mime_crate_parse() {
        // common types are constants
        let text = mime::TEXT_PLAIN;

        assert_eq!(text.subtype(), mime::PLAIN);
    }

    #[test]
    fn test_mime_header_parse_01() {
        /// Test Case: CRLF after the MIME Header
        let buf: &[u8] = b"From: Sender1\r\n";
        match parse_mime_header(buf) {
            Ok((_, res)) => {
                assert_eq!("From", res.key);
                assert_eq!("Sender1", res.value);
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_mime_header_parse_02() {
        /// Test Case: Full MIME Header without CRLF
        let buf: &[u8] = b"From: Sender1";
        match parse_mime_header(buf) {
            Ok((_, res)) => {
                assert!(false);
            }
            Err(nom::Err::Incomplete(err)) => {
                assert!(true);
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test
}
