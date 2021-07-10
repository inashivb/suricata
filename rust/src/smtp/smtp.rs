use crate::mime::{MimeDecEntity, MimeDecConfig, MimeDecSetConfig, MimeDecParseState, CTNT_IS_ATTACHMENT};
use crate::applayer::{AppLayerTxData};
use crate::core;
use crate::core::{SuricataStreamingBufferConfig, AppLayerDecoderEvents};
use crate::conf::*;
use crate::filecontainer::*;


/* content-limit default value */
pub const FILEDATA_CONTENT_LIMIT: u32 = 100000;
/* content-inspect-min-size default value */
pub const FILEDATA_CONTENT_INSPECT_MIN_SIZE: u32 = 32768;
pub const FILEDATA_CONTENT_INSPECT_WINDOW: u32 = 4096;
pub const SMTP_RAW_EXTRACTION_DEFAULT_VALUE: bool = false;

pub const SMTP_COMMAND_BUFFER_STEPS: u16 = 5;
/* we are in process of parsing a fresh command.  Just a placeholder.  If we
 * are not in STATE_COMMAND_DATA_MODE, we have to be in this mode */
pub const SMTP_PARSER_STATE_COMMAND_MODE: u8 = 0x00;
/* we are in mode of parsing a command's data.  Used when we are parsing tls
 * or accepting the rfc 2822 mail after DATA command */
pub const SMTP_PARSER_STATE_COMMAND_DATA_MODE: u8 = 0x01;


// TODO: open PR for handling option w cbindgen is https://github.com/eqrion/cbindgen/pull/699
// either wait for it to get merged or try to make this workaround work
// pub type rs_sbcfg = Option<extern "C" fn(SuricataStreamingBufferConfig) -> ()>;

pub struct SMTPConfig {
    decode_mime: bool,
    raw_extraction: bool,
    mime_config: MimeDecConfig,
    content_lim: u32,
    content_inspect_min_size: u32,
    content_inspect_window: u32,
//    sbcfg: rs_sbcfg,
}

impl SMTPConfig {
    pub fn new() -> SMTPConfig {
        SMTPConfig {
            decode_mime: false,
            raw_extraction: false,
            mime_config: MimeDecConfig::default(),
            content_lim: 0,
            content_inspect_min_size: 0,
            content_inspect_window: 0,
//            sbcfg: None,
        }
    }

    pub fn set(&mut self) {
        let content_limit;
        let root = "app-layer.protocols.smtp.mime";
        let conf = conf_get(root);
        match conf {
            Some(_node) => {
                self.decode_mime = conf_get_bool(&(root.to_owned() + "decode-mime"));
                self.mime_config.decode_base64 = conf_get_bool(&(root.to_owned() + "decode-base64"));
                self.mime_config.decode_quoted_printable = conf_get_bool(&(root.to_owned() + "decode-quoted-printable"));
                self.mime_config.extract_urls = conf_get_bool(&(root.to_owned() + "extract-urls"));
                self.mime_config.body_md5 = conf_get_bool(&(root.to_owned() + "body-md5"));
                self.mime_config.header_value_depth = conf_get(&(root.to_owned() + "header-value-depth")).unwrap().to_string().parse::<u32>().unwrap(); // TODO Dangerous
            },
            None => {}
        }
        unsafe {
            MimeDecSetConfig(&mut self.mime_config);
        }
        self.content_lim = FILEDATA_CONTENT_LIMIT;
        self.content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW;
        self.content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE;

        let root2 = "app-layer.protocols.smtp.inspected-tracker";
        let conf = conf_get(root2);
        match conf {
            Some(_node) => {
                if let Some(content_lim) = conf_get(&(root.to_owned() + "content-limit")) {
                    content_limit = content_lim.to_string().parse::<u32>().unwrap();
                } else {
                    content_limit = FILEDATA_CONTENT_LIMIT;
                }
                self.content_lim = content_limit;
                self.content_inspect_window =conf_get(&(root.to_owned() + "content-inspect-min-size")).unwrap_or(&FILEDATA_CONTENT_INSPECT_WINDOW.to_string()).to_string().parse::<u32>().unwrap(); // TODO Dangerous
                self.content_inspect_min_size = conf_get(&(root.to_owned() + "content-inspect-window")).unwrap_or(&FILEDATA_CONTENT_INSPECT_MIN_SIZE.to_string()).to_string().parse::<u32>().unwrap(); // TODO Dangerous
            },
            None => {}
        }
//        if let Some(sbcfg) = self.sbcfg {
//            sbcfg.buf_size = if content_limit > 0 { content_limit } else { 256 };
//        }
        if conf_get("app-layer.protocols.smtp.raw-extraction").is_some() {
            self.raw_extraction = SMTP_RAW_EXTRACTION_DEFAULT_VALUE;
        }
        if (self.raw_extraction && self.decode_mime) == true {
            self.raw_extraction = false;
        }
    }
}

#[no_mangle]
pub extern "C" fn smtp_configure(smtp_config: &mut SMTPConfig) -> i8 {
    smtp_config.set();
    0
}

#[cfg(test)]
mod test {
    use super::*;

//    #[test]
//    fn test_smtp_configure() {
//        let smtp_conf = "
//            %YAML 1.1\n
//            ---\n
//            app-layer:\n
//              protocols:\n
//                smtp:\n
//                  enabled: yes\n
//                  raw-extraction: no\n
//                  mime:\n
//                    decode-mime: yes\n
//                    decode-base64: yes\n
//                    decode-quoted-printable: yes\n
//                    header-value-depth: 2000\n
//                    extract-urls: yes\n
//                    body-md5: no\n
//            ";
//        let mut smtp_config = SMTPConfig::new();
//        smtp_config.set();
//        assert_eq!(true, smtp_config.decode_mime);
//    }
}
