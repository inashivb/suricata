/* Copyright (C) 2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use std;
use crate::core::{self, *};
use std::mem::transmute;
use crate::applayer::{self, *};
use crate::filecontainer::*;
use crate::conf::*;
use std::ffi::CString;
use crate::smtp::mime;
use crate::smtp::mime::{MimeDecode};
use nom;
//use super::parser;
use mailparse::headers::Headers;
use mailparse::MailHeader;

pub static mut ALPROTO_SMTP: AppProto = ALPROTO_UNKNOWN;
/* content-limit default value */
pub const FILEDATA_CONTENT_LIMIT: u32 = 100000;
/* content-inspect-min-size default value */
pub const FILEDATA_CONTENT_INSPECT_MIN_SIZE: u32 = 32768;
pub const FILEDATA_CONTENT_INSPECT_WINDOW: u16 = 4096;
pub const SMTP_RAW_EXTRACTION_DEFAULT_VALUE: u8 = 0;
pub const SMTP_MAX_REQUEST_AND_REPLY_LINE_LENGTH: u16 = 510;
pub const SMTP_COMMAND_BUFFER_STEPS: u16 = 5;
/* we are in process of parsing a fresh command.  Just a placeholder.  If we
 * are not in STATE_COMMAND_DATA_MODE, we have to be in this mode */
pub const SMTP_PARSER_STATE_COMMAND_MODE: u8 = 0x00;
/* we are in mode of parsing a command's data.  Used when we are parsing tls
 * or accepting the rfc 2822 mail after DATA command */
pub const SMTP_PARSER_STATE_COMMAND_DATA_MODE: u8 = 0x01;
/* Used when we are still in the process of parsing a server command.  Used
 * with multi-line replies and the stream is fragmented before all the lines
 * for a response is seen */
pub const SMTP_PARSER_STATE_PARSING_SERVER_RESPONSE: u8 = 0x02;
pub const SMTP_PARSER_STATE_FIRST_REPLY_SEEN: u8 = 0x04;
pub const SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY: u8 = 0x08;
pub const SMTP_PARSER_STATE_PIPELINING_SERVER: u8 = 0x10;
/* Different EHLO extensions.  Not used now. */
pub const SMTP_EHLO_EXTENSION_PIPELINING: u8 = 7;
pub const SMTP_EHLO_EXTENSION_SIZE: u8 = 8;
pub const SMTP_EHLO_EXTENSION_DSN: u8 = 9;
pub const SMTP_EHLO_EXTENSION_STARTTLS: u8 = 10;
pub const SMTP_EHLO_EXTENSION_8BITMIME: u8 = 11;
/* MIME Error codes */
pub const MIME_DEC_OK: u8 = 0;
pub const MIME_DEC_MORE: u8 = 1;
pub const MIME_DEC_ERR_DATA: i8 = -1;
pub const MIME_DEC_ERR_MEM: i8 = -2;
pub const MIME_DEC_ERR_PARSE: i8 = -3;
pub const MIME_DEC_ERR_STATE: i8 = -4;
/* Anomaly Flags */
pub const ANOM_INVALID_BASE64: u16 = 1;  /* invalid base64 chars */
pub const ANOM_INVALID_QP: u16 = 2;  /* invalid quoted-printable chars */
pub const ANOM_LONG_HEADER_NAME: u16 = 4;  /* header is abnormally long */
pub const ANOM_LONG_HEADER_VALUE: u16 = 8;  /* header value is abnormally long
                                            * (includes multi-line) */
pub const ANOM_LONG_LINE: u16 = 16;  /* Lines that exceed 998 octets */
pub const ANOM_LONG_ENC_LINE: u16 = 32;  /* Lines that exceed 76 octets */
pub const ANOM_MALFORMED_MSG: u16 = 64;  /* Misc msg format errors found */
pub const ANOM_LONG_BOUNDARY: u16 = 128;  /* Boundary too long */
pub const ANOM_LONG_FILENAME: u16 = 256;  /* filename truncated */

// TODO take these out cleanly in core.rs
pub const FILE_STORE: u16      = 0b01010;
pub const FILE_NOMD5: u16      = 0b00010;
pub const FILE_NOMAGIC: u16    = 0b00000;
pub const FILE_USE_DETECT: u16 = 0b01101;


pub static mut SURICATA_SMTP_FILE_CONFIG: Option<&'static SuricataFileContext> = None;

#[no_mangle]
pub extern "C" fn rs_smtp_init(context: &'static mut SuricataFileContext) {
    unsafe {
        SURICATA_SMTP_FILE_CONFIG = Some(context);
    }
}

/* Various SMTP commands
 * We currently have var-ified just STARTTLS and DATA, since we need to them
 * for state transitions.  The rest are just indicate as OTHER_CMD.  Other
 * commands would be introduced as and when needed
 * */
#[derive(Debug, PartialEq, Clone, Copy)]
enum SmtpCommand {
    Helo,
    StartTls,
    MailFrom,
    RcptTo,
    Rset,
    Bdat,
    Data,
    /* not an actual command per se, but the mode where we accept the mail after
     * DATA has it's own reply code for completion, from the server.  We give this
     * stage a pseudo command of it's own, so that we can add this to the command
     * buffer to match with the reply */
    DataMode,
    Unknown,
}

enum DecoderEvent {
    SmtpDecoderEventInvalidReply,
    SmtpDecoderEventUnableToMatchReplyWithRequest,
    SmtpDecoderEventMaxCommandLineLenExceeded,
    SmtpDecoderEventMaxReplyLineLenExceeded,
    SmtpDecoderEventInvalidPipelinedSequence,
    SmtpDecoderEventBdatChunkLenExceeded,
    SmtpDecoderEventNoServerWelcomeMessage,
    SmtpDecoderEventTlsRejected,
    SmtpDecoderEventDataCommandRejected,

    /* Mime Events */
    SmtpDecoderEventMimeParseFailed,
    SmtpDecoderEventMimeMalformedMsg,
    SmtpDecoderEventMimeInvalidBase64,
    SmtpDecoderEventMimeInvalidQP,
    SmtpDecoderEventMimeLongLine,
    SmtpDecoderEventMimeLongEncLine,
    SmtpDecoderEventMimeLongHeaderName,
    SmtpDecoderEventMimeLongHeaderValue,
    SmtpDecoderEventMimeBoundaryTooLong,
    SmtpDecoderEventMimeLongFilename,

    /* Invalid behavior or content */
    SmtpDecoderEventDuplicateFields,
    SmtpDecoderEventUnparsableContent,
}

/* smtp reply codes.  If an entry is made here, please make a simultaneous
 * entry in smtp_reply_map */
enum SMTPCode {
    SmtpReply211,
    SmtpReply214,
    SmtpReply220,
    SmtpReply221,
    SmtpReply235,
    SmtpReply250,
    SmtpReply251,
    SmtpReply252,

    SmtpReply334,
    SmtpReply354,

    SmtpReply421,
    SmtpReply450,
    SmtpReply451,
    SmtpReply452,
    SmtpReply455,

    SmtpReply500,
    SmtpReply501,
    SmtpReply502,
    SmtpReply503,
    SmtpReply504,
    SmtpReply550,
    SmtpReply551,
    SmtpReply552,
    SmtpReply553,
    SmtpReply554,
    SmtpReply555,
}

pub fn smtp_decode_event(t: u8) -> String {
    match t {
        SmtpDecoderEventIvalidReply => "INVALID_REPLY",
        SmtpDecoderEventUnableToMatchReplyWithRequest => "UNABLE_TO_MATCH_REPLY_WITH_REQUEST",
        SmtpDecoderEventMaxCommandLineLenExceeded => "MAX_COMMAND_LINE_LEN_EXCEEDED",
        SmtpDecoderEventMaxReplyLineLenExceeded => "MAX_REPLY_LINE_LEN_EXCEEDED",
        SmtpDecoderEventInvalidPipelinedSequence => "INVALID_PIPELINED_SEQUENCE",
        SmtpDecoderEventBDATChunk => "BDAT_CHUNK_LEN_EXCEEDED",
        SmtpDecoderEventNO_SERVER_WELCOME_MESSAGE => "NO_SERVER_WELCOME_MESSAGE",
        SmtpDecoderEventTLS_REJECTED => "TLS_REJECTED",
        SmtpDecoderEventDATA_COMMAND_REJECTED => "DATA_COMMAND_REJECTED",

        /* Mime Events */
        SmtpDecoderEventMime_PARSE_FAILED => "MIME_PARSE_FAILED",
        SmtpDecoderEventMime_MALFORMED_MSG => "MIME_MALFORMED_MSG",
        SmtpDecoderEventMime_INVALID_BASE64 => "MIME_INVALID_BASE64",
        SmtpDecoderEventMime_INVALID_QP => "MIME_INVALID_QP",
        SmtpDecoderEventMime_LONG_LINE => "MIME_LONG_LINE",
        SmtpDecoderEventMime_LONG_ENC_LINE => "MIME_LONG_ENC_LINE",
        SmtpDecoderEventMime_LONG_HEADER_NAME => "MIME_LONG_HEADER_NAME",
        SmtpDecoderEventMime_LONG_HEADER_VALUE => "MIME_LONG_HEADER_VALUE",
        SmtpDecoderEventMime_BOUNDARY_TOO_LONG => "MIME_LONG_BOUNDARY",
        SmtpDecoderEventMime_LONG_FILENAME => "MIME_LONG_FILENAME",

        /* Invalid behavior or content */
        SmtpDecoderEventDUPLICATE_FIELDS => "DUPLICATE_FIELDS",
        SmtpDecoderEventUNPARSABLE_CONTENT => "UNPARSABLE_CONTENT",
        _ => {
            return (t).to_string();
        }
    }
    .to_string()
}

pub fn smtp_reply(t: u8) -> String {
    match t {
        SmtpReply211 => "211",
        SmtpReply214 => "214",
        SmtpReply220 => "220",
        SmtpReply221 => "221",
        SmtpReply235 => "235",
        SmtpReply250 => "250",
        SmtpReply251 => "251",
        SmtpReply252 => "252",

        SmtpReply334 => "334",
        SmtpReply354 => "354",

        SmtpReply421 => "421",
        SmtpReply450 => "450",
        SmtpReply451 => "451",
        SmtpReply452 => "452",
        SmtpReply455 => "455",

        SmtpReply500 => "500",
        SmtpReply501 => "501",
        SmtpReply502 => "502",
        SmtpReply503 => "503",
        SmtpReply504 => "504",
        SmtpReply550 => "550",
        SmtpReply551 => "551",
        SmtpReply552 => "552",
        SmtpReply553 => "553",
        SmtpReply554 => "554",
        SmtpReply555 => "555",
    }.to_string()
}

#[derive(Debug)]
pub struct SMTPTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,
    pub mime_decoder: Option<MimeDecode>,
    pub anomaly_flags: u16,
    done: bool,
    mail_from: Vec<u8>,
    rcpt_to: Vec<String>,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
}

impl SMTPTransaction {
    pub fn new() -> SMTPTransaction {
        SMTPTransaction {
            tx_id: 0,
            request: None,
            response: None,
            mime_decoder: None,
            anomaly_flags: 0,
            done: false,
            mail_from: Vec::new(),
            rcpt_to: Vec::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
        }
    }


    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }

    fn flag_detect_state_new_file(&mut self) {
        if let Some(de_state) = self.de_state {
            SCLogDebug!("DETECT_ENGINE_STATE_FLAG_FILE_NEW set");
            // TODO convert this into a C func and then extern in Rust
            //de_state.dir_state[0].flags |= DETECT_ENGINE_STATE_FLAG_FILE_NEW;
        } else {
            SCLogDebug!("DETECT_ENGINE_STATE_FLAG_FILE_NEW NOT set, no TX DESTATE");
        }
    }

    pub fn new_file(&mut self, file: &mut FileContainer, smtp_config: SMTPConfig) {
        //debug_validate_bug_on!(file.is_none());
        let tx_id = self.tx_id;
        self.flag_detect_state_new_file();
        FileContainer::file_set_txid_on_last_file(file, tx_id);
        FileContainer::file_set_inspect_sizes(file,
                                              smtp_config.content_inspect_window,
                                              smtp_config.content_inspect_min_size);
    }

}

impl Drop for SMTPTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct MimeDecConfig {
    decode_base64: i32,
    decode_quoted_printable: i32,
    extract_urls: i32,
    bode_md5: i32,
    header_value_depth: u32,
}

pub struct SMTPConfig {
    decode_mime: i32,
    raw_extraction: i32,
    mime_config: Option<MimeDecConfig>,
    content_lim: u32,
    content_inspect_min_size: u32,
    content_inspect_window: u32,
    sbcfg: Option<SuricataStreamingBufferConfig>,
}

impl SMTPConfig {
    pub fn new() -> SMTPConfig {
        SMTPConfig {
            decode_mime: 0,
            raw_extraction: 0,
            mime_config: None,
            content_lim: 0,
            content_inspect_min_size: 0,
            content_inspect_window: 0,
            sbcfg: None,
        }
    }
}

#[derive(Debug)]
pub struct SMTPState {
    tx_id: u64,
    transactions: Vec<SMTPTransaction>,
    request_gap: bool,
    response_gap: bool,
    direction: u8,    // Probably need this
    current_line: Vec<u8>,
    current_line_delim_len: u8,
    input: Vec<u8>,
    tc_db: Vec<u8>,
    tc_current_line_db: u8,
    tc_current_line_lf_seen: u8,
    ts_db: Vec<u8>,
    ts_current_line_db: u8,
    ts_current_line_lf_seen: u8,
    ts_data_cnt: u64,
    ts_last_data_stamp: u64,
    parser_state: u8,
    current_cmd: SmtpCommand,
    bdat_chunk_len: u32,
    bdat_chunk_idx: u32,
    cmds: Vec<SmtpCommand>,
    cmds_buf_len: u16,
    cmds_idx: u16,
    helo: Vec<u8>,
    files: Files,
    file_track_id: u32,
}

impl SMTPState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            request_gap: false,
            response_gap: false,
            direction: core::STREAM_TOSERVER,
            current_line: Vec::new(),
            current_line_delim_len: 0,
            input: Vec::new(),
            tc_db: Vec::new(),
            tc_current_line_db: 0,
            tc_current_line_lf_seen: 0,
            ts_db: Vec::new(),
            ts_current_line_db: 0,
            ts_current_line_lf_seen: 0,
            ts_data_cnt: 0,
            ts_last_data_stamp: 0,
            parser_state: 0,
            current_cmd: SmtpCommand::Unknown,
            bdat_chunk_len: 0,
            bdat_chunk_idx: 0,
            cmds: Vec::new(),
            cmds_buf_len: 0,
            cmds_idx: 0,
            helo: Vec::new(),
            files: Files::new(),
            file_track_id: 0,
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&mut SMTPTransaction> {
        for tx in &mut self.transactions {
            println!("tx.tx_id: {:?}, tx_id: {:?}", tx.tx_id, tx_id);
            if tx.tx_id == tx_id {
                println!("returning some tx");
                return Some(tx);
            }
        }
        return None;
    }

    pub fn get_cur_tx(&mut self) -> Option<&mut SMTPTransaction> {
        println!("self.tx_id: {:?}", self.tx_id);
        let tx_id = self.tx_id;
        self.get_tx(tx_id)
    }

    fn new_tx(&mut self) -> SMTPTransaction {
        let mut tx = SMTPTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut SMTPTransaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn set_event(&mut self, e: DecoderEvent) {
        if let Some(cur_tx) = self.get_cur_tx() {
            core::sc_app_layer_decoder_events_set_event_raw(&mut cur_tx.events, e as u8);
            return;
        }
    }

    fn set_tx_complete(&mut self) {
        let cur_tx = self.get_cur_tx().unwrap();
        cur_tx.done = true;
    }

    fn set_mime_events(&mut self) {
        let tx = self.get_cur_tx().unwrap();
        let mime_dec = tx.mime_decoder.as_ref().unwrap();
        if !mime_dec.headers {
            return;
        }
        // Generate decoder events
        match tx.anomaly_flags {
            ANOM_INVALID_BASE64 => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeInvalidBase64);
            },
            ANOM_INVALID_QP => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeInvalidQP);
            },
            ANOM_LONG_LINE => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeLongLine);
            },
            ANOM_LONG_ENC_LINE => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeLongEncLine);
            },
            ANOM_LONG_HEADER_NAME => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeLongHeaderName);
            },
            ANOM_LONG_HEADER_VALUE => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeLongHeaderValue);
            },
            ANOM_MALFORMED_MSG => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeMalformedMsg);
            },
            ANOM_LONG_BOUNDARY => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeBoundaryTooLong);
            },
            ANOM_LONG_FILENAME => {
                self.set_event(DecoderEvent::SmtpDecoderEventMimeLongFilename);
            },
            _ => {

            }
        }
    }

    fn get_line(&mut self) -> i32 {
        match self.direction {
            core::STREAM_TOSERVER => {
                if self.ts_current_line_lf_seen == 1 {
                    // We have seen the LF for previous line. Clear the parser details 
                    // to parse new line
                    self.ts_current_line_lf_seen = 0;
                    if self.ts_current_line_db == 1 {
                        self.ts_current_line_db = 0;
                        self.current_line = Vec::new();
                    }
                }
                let lf_idx = self.input.iter().position(|&x| x == 0x0a);
                println!("lf_idx: {:?}", lf_idx);
                match lf_idx {
                    Some(idx) => {
                        self.ts_current_line_lf_seen = 1;
                        if self.ts_current_line_db == 1 {
                            self.ts_db.append(&mut self.input.to_vec());
                            let ts_len = self.ts_db.len();
                            if ts_len > 1 && self.ts_db[ts_len - 2] == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.current_line = self.ts_db.clone();
                        } else {
                            self.current_line = self.input.clone();
                            if self.input[0] != idx as u8 && idx as u8 - 1 == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.input = self.input[idx + 1..].to_vec();
                        }
                        return idx as i32;
                    },
                    None => {
                        /* fragmented lines.  Decoder event for special cases.  Not all
                         * fragmented lines should be treated as a possible evasion
                         * attempt.  With multi payload smtp chunks we can have valid
                         * cases of fragmentation.  But within the same segment chunk
                         * if we see fragmentation then it's definitely something you
                         * should alert about */
                        if self.ts_current_line_db == 0 {
                            self.ts_current_line_db = 1;
                            self.ts_db.append(&mut self.input.to_vec());
                        } else {
                            self.ts_db.append(&mut self.input.to_vec());
                        }
                        // input should probably be zero
                        println!("fragmented line failure");
                        return -1;
                    }
                }

            },
            _ => {
                if self.tc_current_line_lf_seen == 1 {
                    // We have seen the LF for previous line. Clear the parser details 
                    // to parse new line
                    self.tc_current_line_lf_seen = 0;
                    if self.tc_current_line_db == 1 {
                        self.tc_current_line_db = 0;
                        self.current_line = Vec::new();
                    }
                }
                let lf_idx = self.input.iter().position(|&x| x == 0x0a);
                match lf_idx {
                    Some(idx) => {
                        self.tc_current_line_lf_seen = 1;
                        if self.tc_current_line_db == 1 {
                            self.tc_db.append(&mut self.input.to_vec());
                            let tc_len = self.tc_db.len();
                            if tc_len > 1 && self.tc_db[tc_len - 2] == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.current_line = self.tc_db.clone();
                        } else {
                            self.current_line = self.input.clone();
                            if self.input[0] != idx as u8 && idx as u8 - 1 == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.input = self.input[idx + 1..].to_vec();
                        }
                        return idx as i32;
                    },
                    None => {
                        /* fragmented lines.  Decoder event for special cases.  Not all
                         * fragmented lines should be treated as a possible evasion
                         * attempt.  With multi payload smtp chunks we can have valid
                         * cases of fragmentation.  But within the same segment chunk
                         * if we see fragmentation then it's definitely something you
                         * should alert about */
                        if self.tc_current_line_db == 0 {
                            self.tc_current_line_db = 1;
                            self.tc_db.append(&mut self.input.to_vec());
                        } else {
                            self.tc_db.append(&mut self.input.to_vec());
                        }
                        // input should probably be zero
                        println!("framented lines 656");
                        return -1;
                    }
                }
            },
        }
    }

    fn process_cmd_starttls(&mut self) -> i8 {
        0
    }

    pub fn get_tx_with_files(&mut self)
        -> Option<(&mut SMTPTransaction, &mut FileContainer, u16)>
    {
        let tx_ref = self.transactions.last_mut();
        let (files, flags) = self.files.get(STREAM_TOSERVER);
        return Some((tx_ref.unwrap(), files, flags));
    }

    pub fn process_data_chunk(&mut self, smtp_config: SMTPConfig, chunk: &[u8], len: u32, flags: &mut u16) -> i8 {
        let ret = MIME_DEC_OK;
        let mut depth = 0;
        //let mut files: FileContainer;

        // TODO bring this out in the request method
        // let flags = unsafe { FileFlowToFlags(flow, STREAM_TOSERVER) };
        // we depend on detection engine for file pruning
        *flags |= FILE_USE_DETECT;

        // Find file
        // From Wikipedia: 
        // Def 1: BEST WAY TO FIGURE OUT IF ITS AN ATTACHMENT
        // In addition to the presentation style, the field Content-Disposition
        // also provides parameters for specifying the name of the file, the creation date and 
        // modification date, which can be used by the reader's mail user agent to store the 
        // attachment.
        // Def 2:
        // text plus attachments (multipart/mixed with a text/plain part and other non-text 
        // parts). A MIME message including an attached file generally indicates the file's 
        // original name with the field "Content-Disposition", so that the type of file is 
        // indicated both by the MIME content-type and the (usually OS-specific) filename extension
        //

        depth = smtp_config.content_inspect_min_size as u64 + self.ts_data_cnt - self.ts_last_data_stamp;
        if let Some((cur_tx, files, xxx)) = self.get_tx_with_files() {
            if let Some(mime_dec) = cur_tx.mime_decoder.as_ref() {
                if mime_dec.headers {
                    if mime_dec.parsable_body {
                        // TODO print file content
                        /* Set storage flag if applicable since only the first file in the
                         * flow seems to be processed by the 'filestore' detector */
                        //                    if (files.head.is_some() && (files.head.flags & FILE_STORE)) {
                        //                        flags |= FILE_STORE; // TODO add this macro
                        //                    }
                        // StreamTcpReassemblySetMinInspectDepth(flow->protoctx, STREAM_TOSERVER, depth)
                        unsafe {
                            files.file_open(SURICATA_SMTP_FILE_CONFIG.unwrap(), &0 /* track ID TODO*/, &chunk, *flags);
                        }
                        // TODO SMTPNewFile
                        /* If close in the same chunk, then pass in empty bytes */
                        // TODO set body end to true if all the data (not just header but body) was parsed
                        // successfully
                        // Since the body would have been parsed already by the crate                   if dec_state.body_end {
                        files.file_close(&0 /* track ID TODO */, *flags);
                        depth = self.ts_data_cnt - self.ts_last_data_stamp;
                        // AppLayerParserTriggerRawStreamReassembly(flow, STREAM_TOSERVER);
                        // StreamTcpReassemblySetMinInspectDepth(flow->protoctx, STREAM_TOSERVER, depth);
                        //                    }
                    }
//                } else if mime::parse(&chunk) > 0 {   // TODO parse is incorrect here, add a flag to mark completion
//                    files.file_close(&0 /* track ID TODO */, *flags);
                    // AppLayerParserTriggerRawStreamReassembly(flow, STREAM_TOSERVER);
                    // StreamTcpReassemblySetMinInspectDepth(flow->protoctx, STREAM_TOSERVER, depth);
                }
                  else {
                    /* Append data chunk to file */
                    files.file_append(&0 /* track ID TODO */, chunk, false /* is_gap TODO */);
                    //                if files.tail && files.tail.content_inspected == 0 && files.tail.size >= smtp_config.content_inspect_min_size {
                    //                    depth = smtp_config.content_inspect_min_size as u64 + self.ts_data_cnt - self.ts_last_data_stamp;
                    //                    // AppLayerParserTriggerRawStreamReassembly(flow, STREAM_TOSERVER);
                    //                    // StreamTcpReassemblySetMinInspectDepth(flow->protoctx, STREAM_TOSERVER, depth);
                    //                    /* after the start of the body inspection, disable the depth logic */
                    //                } else if files.tail && files.tail.content_inspected > 0 {
                    //                    // StreamTcpReassemblySetMinInspectDepth(flow->protoctx, STREAM_TOSERVER, depth);
                    //                /* expand the limit as long as we get file data, as the file data is bigger on the
                    //                 * wire due to base64 */
                    //                } else {
                    //                    depth = smtp_config.content_inspect_min_size as u64 + self.ts_data_cnt - self.ts_last_data_stamp;
                    //                    // StreamTcpReassemblySetMinInspectDepth(flow->protoctx, STREAM_TOSERVER, depth);
                    //                }
                }
            }
        }
    //} else {
            // print body is not a ctnt_attachment
        //}
        return 0;
    }

    fn insert_cmd_into_buf(&mut self, cmd: SmtpCommand) -> i8 {
        if self.cmds.len() as u16 >= self.cmds_buf_len {
            let mut inc = SMTP_COMMAND_BUFFER_STEPS;
            if self.cmds_buf_len + SMTP_COMMAND_BUFFER_STEPS > u16::MAX {
                inc = u16::MAX - self.cmds_buf_len;
            }
            self.cmds_buf_len += inc;
        }
        if self.cmds.len() >= 1 && (self.cmds.last() == Some(SmtpCommand::StartTls).as_ref() || self.cmds.last() == Some(SmtpCommand::Data).as_ref()) {
            // decoder event
            self.set_event(DecoderEvent::SmtpDecoderEventInvalidPipelinedSequence);
            /* we have to have EHLO, DATA, VRFY, EXPN, TURN, QUIT, NOOP,
            * STARTTLS as the last command in pipelined mode */
        }

        // there's a todo in C code here, ask about it
        // maybe set the correct decoder event
        if self.cmds.len() + 1 > u16::MAX.into() {
            return -1;
        }
        self.cmds.push(cmd);
        0
    }

    fn process_cmd_data(&mut self, smtp_config: SMTPConfig) -> i8 {
        if self.parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE == 0 {
            /* looks like are still waiting for a confirmation from the server */
            return 0;
        }
        let single_dot = self.current_line.len() == 1 && char::from(self.current_line[0]) == '.';
        let mut hack_dont_know_what_this_does = false;

        let line = self.current_line.clone();
        self.current_line = Vec::new();

        if let Some((cur_tx, files, xxx)) = self.get_tx_with_files() {
            if let Some(mime_dec) = cur_tx.mime_decoder.as_ref() {
                if single_dot {
                    hack_dont_know_what_this_does = true;
                    if smtp_config.raw_extraction > 0 {
                        /* we use this as the signal that message data is complete. */
                        files.file_close(&0 /* TODO track ID */, 0);
                    } else if smtp_config.decode_mime > 0 && mime_dec.headers { // TODO global smtp_config + mime_State
                        // Complete parsing task
//                        let ret  = mime::parse(&self.current_line);  // TODO is_parsable won't work here since a line is being passed here
//                        if ret as u8 != MIME_DEC_OK {
//                            self.set_event(DecoderEvent::SmtpDecoderEventMimeParseFailed);
//                        }
                        // Generate decoder events
                        self.set_mime_events();
                    }
                    self.set_tx_complete();
                } else if smtp_config.raw_extraction > 0 {
                    // message not over, store the line. This is a substitution of ProcessDataChunk
                    files.file_append(&0 /* track ID TODO */, &line, false /* is gap TODO */);
                }
            }
        }
        if hack_dont_know_what_this_does {
            self.parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            /* kinda like a hack.  The mail sent in DATA mode, would be
             * acknowledged with a reply.  We insert a dummy command to
             * the command buffer to be used by the reply handler to match
             * the reply received */
            self.insert_cmd_into_buf(SmtpCommand::DataMode);
        }
        // If DATA, parse out a MIME message
        if self.current_cmd == SmtpCommand::Data &&
            (self.parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE != 0) {
            let cur_tx = self.get_cur_tx().unwrap();
            let mime_dec = cur_tx.mime_decoder.as_ref().unwrap();
            if smtp_config.decode_mime > 0 && mime_dec.headers {
//                if mime::parse(&self.current_line) > 0 {
//                    // Generate decoder events
//                    self.set_mime_events();
//                    self.set_event(DecoderEvent::SmtpDecoderEventMimeParseFailed);
//                    /* keep the parser in its error state so we can log that,
//                    * the parser will reject new data */
//                } else {
//                        self.set_mime_events();
//                        self.set_event(DecoderEvent::SmtpDecoderEventMimeParseFailed);
//                }
            }
        }
        0
    }

    fn process_cmd_bdat(&mut self) -> i8 {
        self.bdat_chunk_idx += self.current_line.len() as u32 + self.current_line_delim_len as u32;
        if self.bdat_chunk_idx > self.bdat_chunk_len {
            self.parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            // decoder event
            self.set_event(DecoderEvent::SmtpDecoderEventBdatChunkLenExceeded);
            return -1;
        } else if self.bdat_chunk_idx == self.bdat_chunk_len {
            self.parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        }
        0
    }

    fn parse_cmd_bdat(&mut self) -> i8 {
        let i = self.current_line.iter().position(|&x| char::from(x) != ' ').unwrap();
        if i == 4 || i == self.current_line.len() {
            // decoder event
            return -1;
        }
        let s = match std::str::from_utf8(&self.current_line[i..]) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        match s.split_whitespace().collect::<Vec<_>>()[0].parse::<u32>() {
            Ok(val) => {
                self.bdat_chunk_len = val;
            }
            _ => {
                // decoder event
                return -1;
            }
        }
        0
    }

    fn parse_cmd_w_param(&mut self, pref: u8, target: &mut Vec<u8>) {
        println!("current_line: {:?}", self.current_line);
        let i = self.current_line[(pref + 1) as usize..].iter().position(|&x| char::from(x) != ' ').unwrap();
        println!("i={:?}", i);
        /* rfc1870: with the size extension the mail from can be followed by an option.
        We use the space separator to detect it. */
        let spc_i = self.current_line[i as usize..].iter().position(|&x| char::from(x) == ' ').unwrap();
        println!("spc_i={:?}", spc_i);
        target.extend_from_slice(&self.current_line[..spc_i - i + 1]);
    }

    fn parse_cmd_helo(&mut self) -> i32 {
        let mut helo = self.helo.clone();
        if helo.len() > 0 {
            self.set_event(DecoderEvent::SmtpDecoderEventDuplicateFields);
            // TODO this retval should be something other than 0
            return 0;
        }
        self.parse_cmd_w_param(4, &mut helo);
        self.helo = helo;
        0
    }

    fn parse_cmd_mail_from(&mut self) -> i32 {
        let mut cur_tx = self.get_cur_tx().unwrap();
        let mut mail_from = cur_tx.mail_from.clone();
        if mail_from.len() > 0 {
            self.set_event(DecoderEvent::SmtpDecoderEventDuplicateFields);
            // TODO this retval should be something other than 0
            return 0;
        }
        self.parse_cmd_w_param(9, &mut mail_from);
        let mut cur_tx = self.get_cur_tx().unwrap();
        cur_tx.mail_from = mail_from;
        0
    }

    fn parse_cmd_rcpt_to(&mut self) -> i32 {
        println!("txs: {:?}", self.transactions);
        let mut rcpt_to = Vec::new();
        self.parse_cmd_w_param(7, &mut rcpt_to);
        let s = match std::str::from_utf8(&rcpt_to) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        let mut cur_tx = self.get_cur_tx().unwrap();
        cur_tx.rcpt_to.push(s.to_string());
        0
    }

    fn no_new_tx(&self) -> i8 {
        if !(self.parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE) > 0 {
            if self.current_line.len() >= 4 {
                match std::str::from_utf8(&self.current_line) {
                    Ok("rset") | Ok("quit") => { return 1; },
                    _ => {
                        SCLogError!("SMTP current line could not be decoded");
                        return -1;
                    }
                }
            }
        }
        return 0;
    }


    fn process_tx_for_request(&mut self) -> &mut SMTPTransaction {
        let no_new_tx = self.no_new_tx();
        match self.get_cur_tx() {
            Some(tx) => {
                println!("tx was found");
                if tx.done == true && no_new_tx == 0 {
                    let mut new_tx = self.new_tx();
                    self.transactions.push(new_tx);
                }
                let ts_dcount = self.ts_data_cnt;
                self.ts_last_data_stamp = ts_dcount;
                // TODO StreamTcpReassemblySetMinInspectDepth stuff
                self.transactions.last_mut().unwrap()
            },
            None => {
                println!("tx was not found");
                let mut new_tx = self.new_tx();
                self.transactions.push(new_tx);
                let ts_dcount = self.ts_data_cnt;
                self.ts_last_data_stamp = ts_dcount;
                // TODO StreamTcpReassemblySetMinInspectDepth stuff
                self.transactions.last_mut().unwrap()
            },
        }
    }

    fn set_current_cmd(&mut self, cur_line_lc: String) {
        if is_cmd_match(cur_line_lc.clone(), "starttls") == true {
            self.current_cmd = SmtpCommand::StartTls;
        } else if is_cmd_match(cur_line_lc.clone(), "data") == true {
            self.current_cmd = SmtpCommand::Data;
        } else if is_cmd_match(cur_line_lc.clone(), "bdat") == true {
            self.current_cmd = SmtpCommand::Bdat;
        } else if is_cmd_match(cur_line_lc.clone(), "helo") == true {
            self.current_cmd = SmtpCommand::Helo;
        } else if is_cmd_match(cur_line_lc.clone(), "ehlo") == true {
            self.current_cmd = SmtpCommand::Helo;
        } else if is_cmd_match(cur_line_lc.clone(), "mail from") == true {
            self.current_cmd = SmtpCommand::MailFrom;
        } else if is_cmd_match(cur_line_lc.clone(), "rcpt to") == true {
            self.current_cmd = SmtpCommand::RcptTo;
        } else if is_cmd_match(cur_line_lc.clone(), "rset") == true {
            self.current_cmd = SmtpCommand::Rset;
        } else {
            self.current_cmd = SmtpCommand::Unknown;
        }
    }

    fn process_request(&mut self, input: &[u8], smtp_config: SMTPConfig) -> i8 {//, applayerparserstate?)
        let current_line_len = self.current_line.len() as u8;
        let current_line_delim_len = self.current_line_delim_len;
        let parser_state = self.parser_state;
        let current_line = self.current_line.clone();
        let cur_tx = self.process_tx_for_request();
        println!("cur tx: {:?}", cur_tx);
        let cur_tx_done = cur_tx.done;
        let ts_dcount = current_line_len + current_line_delim_len;
        let cur_line_lc = match std::str::from_utf8(&current_line) {
            Ok(v) => v.to_lowercase(),
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        if parser_state & SMTP_PARSER_STATE_FIRST_REPLY_SEEN == 0 {
            self.set_event(DecoderEvent::SmtpDecoderEventNoServerWelcomeMessage);
        }
         /* there are 2 commands that can push it into this COMMAND_DATA mode - STARTTLS and DATA */
        if parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE == 0 {
            self.set_current_cmd(cur_line_lc);
            let current_cmd = self.current_cmd;
            match current_cmd {
                SmtpCommand::StartTls => {
                    if current_line_len >= 8 {
                        self.process_cmd_starttls();
                    }
                },
                SmtpCommand::Data => {
                    if current_line_len >= 4 {
                        if smtp_config.raw_extraction > 0 {
                            let msgname = "rawmsg";
                            if self.transactions.len() > 1 && cur_tx_done == false {
                                self.set_event(DecoderEvent::SmtpDecoderEventUnparsableContent);
                                self.files.files_ts.file_close(&0 /* Track ID TODO */, 0 /* flags TODO */);
                                let new_tx = self.new_tx();
                                self.transactions.push(new_tx);
                            }
                            unsafe {
                                if self.files.files_ts.file_open(SURICATA_SMTP_FILE_CONFIG.unwrap(),
                                                                 &0 /* track ID TODO*/,
                                                                 msgname.as_bytes(),
                                                                 FILE_NOMD5|FILE_NOMAGIC|FILE_USE_DETECT) >= 0 { // TODO check if 0 is acceptable
                                    //self.new_file(); // TODO Implement this function
                                }
                            }
                        } else if smtp_config.decode_mime > 0 {
                            let mime_decoder = mime::parse(input);
                            let cur_tx = self.transactions.last_mut().unwrap();
                            cur_tx.mime_decoder = mime_decoder;

                            let cur_tx_headers = cur_tx.mime_decoder.as_ref().unwrap().headers;
                            // check if this transaction already has mime headers
                            // /* We have 2 chained mails and did not detect the end
                            // * of first one. So we start a new transaction.
                            //
                            // TODO probabl this needs to be done on the newly created tx, check again
                            if cur_tx_headers == true {
                                // tx.mime_state.state_flag = PARSE_ERROR; // probably don't need it
                                // anymore
                                self.set_event(DecoderEvent::SmtpDecoderEventUnparsableContent);
                                let new_tx =self.new_tx();
                                self.transactions.push(new_tx);
                            }
                            //cur_tx.mime_headers = mime.parse(current_line).unwrap(); // TODO this is unsafe, what happens in case of an error?
                        }
                        /* Enter immediately data mode without waiting for server reply */
                        if self.parser_state & SMTP_PARSER_STATE_PIPELINING_SERVER != 0 {
                            self.parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
                        }
                        self.process_cmd_data(smtp_config);
                    }
                },
                SmtpCommand::Bdat => {
                    if current_line_len >= 4 {
                        self.parse_cmd_bdat();
                        self.parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
                    self.process_cmd_bdat();
                    }
                },
                SmtpCommand::Helo => {
                    if current_line_len >= 4 {
                        if self.parse_cmd_helo() == -1 {
                            println!("helo cmd failed");
                            return -1;
                        }
                    }
                },
                SmtpCommand::MailFrom => {
                    if current_line_len >= 9 {
                        if self.parse_cmd_mail_from() == -1 {
                            println!("mail_from cmd failed");
                            return -1;
                        }
                    }
                },
                SmtpCommand::RcptTo => {
                    if current_line_len >= 7 {
                        if self.parse_cmd_rcpt_to() == -1 {
                            println!("rcpt_to cmd failed");
                            return -1;
                        }
                    }
                },
                SmtpCommand::Rset => {
                    if current_line_len >= 4 {
                        // Resets chunk index in case of connection reuse
                        self.bdat_chunk_idx = 0;
                    }
                },
                _ => {

                },
            }
            /* Every command is inserted into a command buffer, to be matched
            * against reply(ies) sent by the server */
            self.insert_cmd_into_buf(self.current_cmd);
            return 0;
        }
        0
    }

    fn parse_request(&mut self, input: &[u8], smtp_config: SMTPConfig) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this smtp, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        self.input = input.to_vec();
        let mut consumed = input.len() as i32;
        while consumed > 0 {
            let retval = self.get_line();
            if retval < 0 {
                consumed = 0;
                println!("Getline failed");
                //return AppLayerResult::err();
            } else {
                println!("mail can be saved now");
                consumed -= retval;
            }
//            match parser::parse_message(start) {  // This is for header parsing etc
//                Ok((rem, request)) => {
//                    start = rem;
//
//                    SCLogNotice!("Request: {}", request);
//                    let mut tx = self.new_tx();
//                    tx.request = Some(request);
//                    self.transactions.push(tx);
//                },
//                Err(nom::Err::Incomplete(_)) => {
//                    // Not enough data. This parser doesn't give us a good indication
//                    // of how much data is missing so just ask for one more byte so the
//                    // parse is called as soon as more data is received.
//                    let consumed = input.len() - start.len();
//                    let needed = start.len() + 1;
//                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
//                },
//                Err(_) => {
//                    return AppLayerResult::err();
//                },
//            }
        }
        self.process_request(input, smtp_config);

        // Input was fully consumed.
        return AppLayerResult::ok();
    }
//
//    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
//        // We're not interested in empty responses.
//        if input.len() == 0 {
//            return AppLayerResult::ok();
//        }
//
//        let mut start = input;
//        while start.len() > 0 {
//            match parser::parse_message(start) {
//                Ok((rem, response)) => {
//                    start = rem;
//
//                    match self.find_request() {
//                        Some(tx) => {
//                            tx.response = Some(response);
//                            SCLogNotice!("Found response for request:");
//                            SCLogNotice!("- Request: {:?}", tx.request);
//                            SCLogNotice!("- Response: {:?}", tx.response);
//                        }
//                        None => {}
//                    }
//                }
//                Err(nom::Err::Incomplete(_)) => {
//                    let consumed = input.len() - start.len();
//                    let needed = start.len() + 1;
//                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
//                }
//                Err(_) => {
//                    return AppLayerResult::err();
//                }
//            }
//        }
//
//        // All input was fully consumed.
//        return AppLayerResult::ok();
//    }
//
//    fn tx_iterator(
//        &mut self,
//        min_tx_id: u64,
//        state: &mut u64,
//    ) -> Option<(&SMTPTransaction, u64, bool)> {
//        let mut index = *state as usize;
//        let len = self.transactions.len();
//
//        while index < len {
//            let tx = &self.transactions[index];
//            if tx.tx_id < min_tx_id + 1 {
//                index += 1;
//                continue;
//            }
//            *state = index as u64;
//            return Some((tx, tx.tx_id - 1, (len - index) > 1));
//        }
//
//        return None;
//    }
//
//    fn on_request_gap(&mut self, _size: u32) {
//        self.request_gap = true;
//    }
//
//    fn on_response_gap(&mut self, _size: u32) {
//        self.response_gap = true;
//    }
}

fn is_cmd_match(s: String, cmd: &str) -> bool {
    s.matches(&cmd).collect::<Vec<&str>>().len() > 0
}

////// TODO 3rd priority is retrieving config from suricata.yaml
////fn smtp_configure() {
////    let conf = ConfNode::get_child_value("app-layer.protocols.smtp.mime");
////    match conf {
////        Some(val) => {
////            let bool_config_keys = vec!["decode-mime", "decode-base64", "decode-quoted-printable", "extract-urls", "body-md5"];
////            for i in bool_config_keys.iter() {}
////            // TODO maybe dict way like below won't work, will have to make a struct
////                smtp_config[i] = ConfNode::get_child_bool(i); // TODO global smtp_config
////            smtp_config["header-value-depth"] = ConfNode::get_child_bool("header-value-depth")
////        },
////        None => {}
////    }
////
////    // TODO Pass mime config data to MimeDec API
////    // MimeDecSetConfig(&smtp_config.mime_config);
////    smtp_config.content_limit = FILEDATA_CONTENT_LIMIT;
////    smtp_config.content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW;
////    smtp_config.content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE;
////
////    // TODO child value maybe incorrect here, check again
////    let conf = ConfNode::get_child_value("app-layer.protocols.smtp.inspected-tracker");
////    match conf {
////        Some(val) => {
////            // TODO loop over the child keys and get values
////            // leaving todo to confirm if child value fn does the right thing
////        },
////        None => {}
////    }
////    smtp_config.sbcfg.buf_size = content_limit ? content_limit : 256;
////    if ConfNode::get_child_bool("app-layer.protocols.smtp.raw-extraction") != true {
////        smtp_config.raw_extraction = SMTP_RAW_EXTRACTION_DEFAULT_VALUE;
////    }
////    if smtp_config.raw_extraction && smtp_config.decode_mime {
////        smtp_config.raw_extraction = 0;
////    }
////    0
////}
//
///// TODO Probe for a valid header.
/////
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    Ok((&[1, 0], ()))
}

// C exports.

//export_tx_get_detect_state!(
//    rs_smtp_tx_get_detect_state,
//    SMTPTransaction
//);
//export_tx_set_detect_state!(
//    rs_smtp_tx_set_detect_state,
//    SMTPTransaction
//);
//
///// C entry point for a probing parser.
//#[no_mangle]
//pub extern "C" fn rs_smtp_probing_parser(
//    _flow: *const Flow,
//    _direction: u8,
//    input: *const u8,
//    input_len: u32,
//    _rdir: *mut u8
//) -> AppProto {
//    // Need at least 2 bytes.
//    if input_len > 1 && input != std::ptr::null_mut() {
//        let slice = build_slice!(input, input_len as usize);
//        if probe(slice).is_ok() {
//            return unsafe { ALPROTO_SMTP };
//        }
//    }
//    return ALPROTO_UNKNOWN;
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
//    let state = SMTPState::new();
//    let boxed = Box::new(state);
//    return unsafe { transmute(boxed) };
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_free(state: *mut std::os::raw::c_void) {
//    // Just unbox...
//    let _drop: Box<SMTPState> = unsafe { transmute(state) };
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_tx_free(
//    state: *mut std::os::raw::c_void,
//    tx_id: u64,
//) {
//    let state = cast_pointer!(state, SMTPState);
//    state.free_tx(tx_id);
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_parse_request(
//    _flow: *const Flow,
//    state: *mut std::os::raw::c_void,
//    pstate: *mut std::os::raw::c_void,
//    input: *const u8,
//    input_len: u32,
//    _data: *const std::os::raw::c_void,
//    _flags: u8,
//) -> AppLayerResult {
//    let eof = unsafe {
//        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
//            true
//        } else {
//            false
//        }
//    };
//
//    if eof {
//        // If needed, handled EOF, or pass it into the parser.
//        return AppLayerResult::ok();
//    }
//
//    let state = cast_pointer!(state, SMTPState);
//
//    if input == std::ptr::null_mut() && input_len > 0 {
//        // Here we have a gap signaled by the input being null, but a greater
//        // than 0 input_len which provides the size of the gap.
//        state.on_request_gap(input_len);
//        AppLayerResult::ok()
//    } else {
//        let buf = build_slice!(input, input_len as usize);
//        state.parse_request(buf)
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_parse_response(
//    _flow: *const Flow,
//    state: *mut std::os::raw::c_void,
//    pstate: *mut std::os::raw::c_void,
//    input: *const u8,
//    input_len: u32,
//    _data: *const std::os::raw::c_void,
//    _flags: u8,
//) -> AppLayerResult {
//    let _eof = unsafe {
//        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
//            true
//        } else {
//            false
//        }
//    };
//    let state = cast_pointer!(state, SMTPState);
//
//    if input == std::ptr::null_mut() && input_len > 0 {
//        // Here we have a gap signaled by the input being null, but a greater
//        // than 0 input_len which provides the size of the gap.
//        state.on_response_gap(input_len);
//        AppLayerResult::ok()
//    } else {
//        let buf = build_slice!(input, input_len as usize);
//        state.parse_response(buf).into()
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_get_tx(
//    state: *mut std::os::raw::c_void,
//    tx_id: u64,
//) -> *mut std::os::raw::c_void {
//    let state = cast_pointer!(state, SMTPState);
//    match state.get_tx(tx_id) {
//        Some(tx) => {
//            return unsafe { transmute(tx) };
//        }
//        None => {
//            return std::ptr::null_mut();
//        }
//    }
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_get_tx_count(
//    state: *mut std::os::raw::c_void,
//) -> u64 {
//    let state = cast_pointer!(state, SMTPState);
//    return state.tx_id;
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_progress_completion_status(
//    _direction: u8,
//) -> std::os::raw::c_int {
//    // This parser uses 1 to signal transaction completion status.
//    return 1;
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_tx_get_alstate_progress(
//    tx: *mut std::os::raw::c_void,
//    _direction: u8,
//) -> std::os::raw::c_int {
//    let tx = cast_pointer!(tx, SMTPTransaction);
//
//    // Transaction is done if we have a response.
//    if tx.response.is_some() {
//        return 1;
//    }
//    return 0;
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_get_events(
//    tx: *mut std::os::raw::c_void
//) -> *mut core::AppLayerDecoderEvents {
//    let tx = cast_pointer!(tx, SMTPTransaction);
//    return tx.events;
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_get_event_info(
//    _event_name: *const std::os::raw::c_char,
//    _event_id: *mut std::os::raw::c_int,
//    _event_type: *mut core::AppLayerEventType,
//) -> std::os::raw::c_int {
//    return -1;
//}
//
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
//                                                         _event_name: *mut *const std::os::raw::c_char,
//                                                         _event_type: *mut core::AppLayerEventType
//) -> i8 {
//    return -1;
//}
//#[no_mangle]
//pub extern "C" fn rs_smtp_state_get_tx_iterator(
//    _ipproto: u8,
//    _alproto: AppProto,
//    state: *mut std::os::raw::c_void,
//    min_tx_id: u64,
//    _max_tx_id: u64,
//    istate: &mut u64,
//) -> applayer::AppLayerGetTxIterTuple {
//    let state = cast_pointer!(state, SMTPState);
//    match state.tx_iterator(min_tx_id, istate) {
//        Some((tx, out_tx_id, has_next)) => {
//            let c_tx = unsafe { transmute(tx) };
//            let ires = applayer::AppLayerGetTxIterTuple::with_values(
//                c_tx,
//                out_tx_id,
//                has_next,
//            );
//            return ires;
//        }
//        None => {
//            return applayer::AppLayerGetTxIterTuple::not_found();
//        }
//    }
//}
//
///// Get the request buffer for a transaction from C.
/////
///// No required for parsing, but an example function for retrieving a
///// pointer to the request buffer from C for detection.
//#[no_mangle]
//pub extern "C" fn rs_smtp_get_request_buffer(
//    tx: *mut std::os::raw::c_void,
//    buf: *mut *const u8,
//    len: *mut u32,
//) -> u8
//{
//    let tx = cast_pointer!(tx, SMTPTransaction);
//    if let Some(ref request) = tx.request {
//        if request.len() > 0 {
//            unsafe {
//                *len = request.len() as u32;
//                *buf = request.as_ptr();
//            }
//            return 1;
//        }
//    }
//    return 0;
//}
//
///// Get the response buffer for a transaction from C.
//#[no_mangle]
//pub extern "C" fn rs_smtp_get_response_buffer(
//    tx: *mut std::os::raw::c_void,
//    buf: *mut *const u8,
//    len: *mut u32,
//) -> u8
//{
//    let tx = cast_pointer!(tx, SMTPTransaction);
//    if let Some(ref response) = tx.response {
//        if response.len() > 0 {
//            unsafe {
//                *len = response.len() as u32;
//                *buf = response.as_ptr();
//            }
//            return 1;
//        }
//    }
//    return 0;
//}
//
//export_tx_data_get!(rs_smtp_get_tx_data, SMTPTransaction);
//
//// Parser name as a C style string.
//const PARSER_NAME: &'static [u8] = b"smtp-rust\0";
//
//#[no_mangle]
//pub unsafe extern "C" fn rs_smtp_register_parser() {
//    let default_port = CString::new("[7000]").unwrap();
//    let parser = RustParser {
//        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
//        default_port: default_port.as_ptr(),
//        ipproto: IPPROTO_TCP,
//        probe_ts: Some(rs_smtp_probing_parser),
//        probe_tc: Some(rs_smtp_probing_parser),
//        min_depth: 0,
//        max_depth: 16,
//        state_new: rs_smtp_state_new,
//        state_free: rs_smtp_state_free,
//        tx_free: rs_smtp_state_tx_free,
//        parse_ts: rs_smtp_parse_request,
//        parse_tc: rs_smtp_parse_response,
//        get_tx_count: rs_smtp_state_get_tx_count,
//        get_tx: rs_smtp_state_get_tx,
//        tx_comp_st_ts: 1,
//        tx_comp_st_tc: 1,
//        tx_get_progress: rs_smtp_tx_get_alstate_progress,
//        get_de_state: rs_smtp_tx_get_detect_state,
//        set_de_state: rs_smtp_tx_set_detect_state,
//        get_events: Some(rs_smtp_state_get_events),
//        get_eventinfo: Some(rs_smtp_state_get_event_info),
//        get_eventinfo_byid : Some(rs_smtp_state_get_event_info_by_id),
//        localstorage_new: None,
//        localstorage_free: None,
//        get_files: None,
//        get_tx_iterator: Some(rs_smtp_state_get_tx_iterator),
//        get_tx_data: rs_smtp_get_tx_data,
//        apply_tx_config: None,
//        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
//        truncate: None,
//    };
//
//    let ip_proto_str = CString::new("tcp").unwrap();
//
//    if AppLayerProtoDetectConfProtoDetectionEnabled(
//        ip_proto_str.as_ptr(),
//        parser.name,
//    ) != 0
//    {
//        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
//        ALPROTO_SMTP = alproto;
//        if AppLayerParserConfParserEnabled(
//            ip_proto_str.as_ptr(),
//            parser.name,
//        ) != 0
//        {
//            let _ = AppLayerRegisterParser(&parser, alproto);
//        }
//        SCLogNotice!("Rust smtp parser registered.");
//    } else {
//        SCLogNotice!("Protocol detector and parser disabled for SMTP.");
//    }
//}
//
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_smtp_request_parsing() {
        let request: &[u8] = &[
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x5b, 0x31, 0x39,
        0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x30, 0x2e,
        0x31, 0x35, 0x38, 0x5d, 0x0d, 0x0a
        ];

        let smtp_config = SMTPConfig::new();
        let mut smtp_state = SMTPState::new();
        assert_eq!(AppLayerResult::ok(), smtp_state.parse_request(request, smtp_config));
    }

    #[test]
    fn test_cmd_ehlo() {
        /* EHLO boo.com<CR><LF> */
        let request: &[u8] = &[
            0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
            0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a
        ];
        let smtp_config = SMTPConfig::new();
        let mut smtp_state = SMTPState::new();
        assert_eq!(AppLayerResult::ok(), smtp_state.parse_request(request, smtp_config));
    }

    #[test]
    fn test_cmd_rcpt_to() {
        /* RCPT TO:bimbs@gmail.com<CR><LF> */
        let request: &[u8] = &[
            0x52, 0x43, 0x50, 0x54, 0x20, 0x54, 0x4f, 0x3a,
            0x62, 0x69, 0x6d, 0x62, 0x73, 0x40, 0x67, 0x6d,
            0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d,
            0x0a
        ];
        let smtp_config = SMTPConfig::new();
        let mut smtp_state = SMTPState::new();
        assert_eq!(AppLayerResult::ok(), smtp_state.parse_request(request, smtp_config));
    }

    #[test]
    fn test_cmd_mail_from() {
        /* MAIL FROM:asdff@asdf.com<CR><LF> */
        let request: &[u8] = &[
            0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
            0x4d, 0x3a, 0x61, 0x73, 0x64, 0x66, 0x66, 0x40,
            0x61, 0x73, 0x64, 0x66, 0x2e, 0x63, 0x6f, 0x6d,
            0x0d, 0x0a
        ];
        let smtp_config = SMTPConfig::new();
        let mut smtp_state = SMTPState::new();
        assert_eq!(AppLayerResult::ok(), smtp_state.parse_request(request, smtp_config));
    }

    #[test]
    fn test_cmd_bdat() {
         /* BDAT 51<CR><LF> */
        let request: &[u8] = &[
            0x42, 0x44, 0x41, 0x54, 0x20, 0x35, 0x31, 0x0d,
            0x0a,
        ];
        let smtp_config = SMTPConfig::new();
        let mut smtp_state = SMTPState::new();
        assert_eq!(AppLayerResult::ok(), smtp_state.parse_request(request, smtp_config));
    }

    #[test]
    fn test_cmd_data() {
        /* MAIL FROM:pbsf@asdfs.com<CR><LF>
         * RCPT TO:pbsf@asdfs.com<CR><LF>
         * DATA<CR><LF>
         * Immediate data
         */
        let request: &[u8] = &[
            0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
            0x4d, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
            0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
            0x0d, 0x0a, 0x52, 0x43, 0x50, 0x54, 0x20, 0x54,
            0x4f, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
            0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
            0x0d, 0x0a, 0x44, 0x41, 0x54, 0x41, 0x0d, 0x0a,
            0x49, 0x6d, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74,
            0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0x0d, 0x0a,
        ];
        let smtp_config = SMTPConfig::new();
        let mut smtp_state = SMTPState::new();
        assert_eq!(AppLayerResult::ok(), smtp_state.parse_request(request, smtp_config));
    }
}
