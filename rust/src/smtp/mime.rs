#[cfg(test)]
mod test {
    use mime::Mime;

    #[test]
    fn test_mime_dec_parse_line_01() {
        let mime = Mime::from_str("From: Sender1");
        assert_eq!(mime.source, 1);
    }
}
