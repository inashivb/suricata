extern crate mime;

#[cfg(test)]
mod test {
    #[test]
    fn test_mime_dec_parse_line_01() {
        // common types are constants
        let text = mime::TEXT_PLAIN;

        assert_eq!(text.subtype(), mime::PLAIN);
    }
}
