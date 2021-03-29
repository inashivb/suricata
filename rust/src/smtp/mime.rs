extern crate mailparse;

use mailparse::*;
use mailparse::headers::Headers;


//impl std::fmt::Debug for MimeDecode<'_> {
//    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//        f.debug_struct("MimeDecode")
//            .field("parsable_headers", &self.parsable_headers)
//            .field("parsable_body", &self.parsable_body)
//            .field("ctnt_attachment", &self.ctnt_attachment)
//            .field("headers", &self.headers)
//            .finish()
//    }
//}
//
//#[derive(Debug, Clone)]
//pub struct MimeDecode<'a> {
//    pub parsable_headers: bool,
//    pub parsable_body: bool,
//    pub ctnt_attachment: bool,
//    pub headers: Option<Headers<'a>>,
//}
//
//impl<'a> MimeDecode<'a> {
//    pub fn new() -> MimeDecode<'a> {
//        MimeDecode {
//            parsable_headers: false,
//            parsable_body: false,
//            ctnt_attachment: false,
//            headers: None,
//        }
//    }
//}
//
//
//pub fn parse(data: &[u8]) -> i8 {
//    let mut mime_dec = MimeDecode::new();
//    match parse_mail(&data) {
//        Ok(val) => {
//            mime_dec.parsable_headers = true;
//            mime_dec.parsable_body = true;
//            mime_dec.headers = Some(val.get_headers());
//            mime_dec.ctnt_attachment = if val.headers.get_all_values("Content-Disposition").len() > 0 { true } else { false };
//        }
//        _ => {
//            return -1;
//        }
//    }
//    1
//}

#[derive(Debug, Clone)]
pub struct MimeDecode {
    pub parsable_headers: bool,
    pub parsable_body: bool,
    pub ctnt_attachment: bool,
    pub headers: Option<Vec<u8>>,
}


impl MimeDecode {
    pub fn new() -> MimeDecode {
        MimeDecode {
            parsable_headers: false,
            parsable_body: false,
            ctnt_attachment: false,
            headers: None,
        }
    }
}

pub fn parse(data: &[u8]) -> i8 {
    1
}

#[cfg(test)]
mod test {
    use mailparse::*;

    #[test]
    fn test_mime_full_msg_parse() {
        let parsed = parse_mail(concat!(
            "Subject: This is a test email\n",
            "Content-Type: multipart/alternative; boundary=foobar\n",
            "Date: Sun, 02 Oct 2016 07:06:22 -0700 (PDT)\n",
            "\n",
            "--foobar\n",
            "Content-Type: text/plain; charset=utf-8\n",
            "Content-Transfer-Encoding: quoted-printable\n",
            "\n",
            "This is the plaintext version, in utf-8. Proof by Euro: =E2=82=AC\n",
            "--foobar\n",
            "Content-Type: text/html\n",
            "Content-Transfer-Encoding: base64\n",
            "\n",
            "PGh0bWw+PGJvZHk+VGhpcyBpcyB0aGUgPGI+SFRNTDwvYj4gdmVyc2lvbiwgaW4g \n",
            "dXMtYXNjaWkuIFByb29mIGJ5IEV1cm86ICZldXJvOzwvYm9keT48L2h0bWw+Cg== \n",
            "--foobar--\n",
            "After the final boundary stuff gets ignored.\n").as_bytes())
            .unwrap();
        assert_eq!(parsed.headers.get_first_value("Subject"),
            Some("This is a test email".to_string()));
        assert_eq!(parsed.subparts.len(), 2);
        assert_eq!(parsed.subparts[0].get_body().unwrap(),
            "This is the plaintext version, in utf-8. Proof by Euro: \u{20AC}");
        assert_eq!(parsed.subparts[1].headers[1].get_value(), "base64");
        assert_eq!(parsed.subparts[1].ctype.mimetype, "text/html");
        assert!(parsed.subparts[1].get_body().unwrap().starts_with("<html>"));
        assert_eq!(dateparse(parsed.headers.get_first_value("Date").unwrap().as_str()).unwrap(), 1475417182);
    }

    #[test]
    fn test_mime_header_parse() {
        let parsed = parse_mail("From: Sender2\r\nTo: Recipient2\r\nSubject: subject2\r\nContent-Type: text/plain\r\n\r\nLine 1\r\nLine 2\r\nLine 3\r\n".as_bytes()).unwrap();
        assert_eq!(parsed.headers.get_first_value("From"), Some("Sender2".to_string()));
    }

    #[test]
    fn test_mime_filename_parse() {
        let parsed = parse_mail("Content-Disposition: attachment; filename=\"12characters12characters12characters.exe\";somejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsdsomejunkasfdasfsafasafdsasdasassdssdsd".as_bytes()).unwrap();
        let headers = std::str::from_utf8(parsed.get_headers().get_raw_bytes()).unwrap();
        let ctype = parse_content_type(&headers);
        assert_eq!(ctype.params.get("filename").unwrap().len(), 40);
    }

    #[test]
    fn test_mime_filename_long_parse() {
        let parsed = parse_mail("Content-Disposition: attachment; filename=\"12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters12characters.exe\"".as_bytes()).unwrap();
        let headers = std::str::from_utf8(parsed.get_headers().get_raw_bytes()).unwrap();
        let ctype = parse_content_type(&headers);
        // TODO in C filename is restricted to 256, should the limit be applied here?
        assert_eq!(ctype.params.get("filename").unwrap().len(), 280);
    }
}
