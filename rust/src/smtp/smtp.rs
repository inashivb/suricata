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
use crate::core::{self, ALPROTO_SMTP, AppProto, Flow, IPPROTO_TCP};
use std::mem::transmute;
use crate::applayer::{self, *};
use crate::filecontainer::*;
use crate::conf::*;
use std::ffi::CString;
use nom;
use super::parser;

static mut ALPROTO_SMTP: AppProto = ALPROTO_SMTP;
/* content-limit default value */
pub const FILEDATA_CONTENT_LIMIT: u32 = 100000;
/* content-inspect-min-size default value */
pub const FILEDATA_CONTENT_INSPECT_MIN_SIZE: u32 = 32768;
pub const FILEDATA_CONTENT_INSPECT_WINDOW: u8 = 4096;
pub const SMTP_RAW_EXTRACTION_DEFAULT_VALUE: u8 = 0;
pub const SMTP_MAX_REQUEST_AND_REPLY_LINE_LENGTH: u8 = 510;
pub const SMTP_COMMAND_BUFFER_STEPS: u8 = 5;
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
/* Various SMTP commands
 * We currently have var-ified just STARTTLS and DATA, since we need to them
 * for state transitions.  The rest are just indicate as OTHER_CMD.  Other
 * commands would be introduced as and when needed */
pub const SMTP_COMMAND_STARTTLS: u8 = 1;
pub const SMTP_COMMAND_DATA: u8 = 2;
pub const SMTP_COMMAND_BDAT: u8 = 3;
/* not an actual command per se, but the mode where we accept the mail after
 * DATA has it's own reply code for completion, from the server.  We give this
 * stage a pseudo command of it's own, so that we can add this to the command
 * buffer to match with the reply */
pub const SMTP_COMMAND_DATA_MODE: u8 = 4;
pub const SMTP_COMMAND_OTHER_CMD: u8 = 5;
pub const SMTP_COMMAND_RSET: u8 = 6;
/* Different EHLO extensions.  Not used now. */
pub const SMTP_EHLO_EXTENSION_PIPELINING;
pub const SMTP_EHLO_EXTENSION_SIZE;
pub const SMTP_EHLO_EXTENSION_DSN;
pub const SMTP_EHLO_EXTENSION_STARTTLS;
pub const SMTP_EHLO_EXTENSION_8BITMIME;
/* MIME Error codes */
pub const MIME_DEC_OK: u8 = 0;
pub const MIME_DEC_MORE: u8 = 1;
pub const MIME_DEC_ERR_DATA = -1;
pub const MIME_DEC_ERR_MEM = -2;
pub const MIME_DEC_ERR_PARSE = -3;
pub const MIME_DEC_ERR_STATE = -4;

enum DecoderEvent {
    SMTP_DECODER_EVENT_INVALID_REPLY,
    SMTP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST,
    SMTP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE,
    SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE,
    SMTP_DECODER_EVENT_TLS_REJECTED,
    SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED,

    /* MIME Events */
    SMTP_DECODER_EVENT_MIME_PARSE_FAILED,
    SMTP_DECODER_EVENT_MIME_MALFORMED_MSG,
    SMTP_DECODER_EVENT_MIME_INVALID_BASE64,
    SMTP_DECODER_EVENT_MIME_INVALID_QP,
    SMTP_DECODER_EVENT_MIME_LONG_LINE,
    SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE,
    SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME,
    SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE,
    SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG,
    SMTP_DECODER_EVENT_MIME_LONG_FILENAME,

    /* Invalid behavior or content */
    SMTP_DECODER_EVENT_DUPLICATE_FIELDS,
    SMTP_DECODER_EVENT_UNPARSABLE_CONTENT,
}

/* smtp reply codes.  If an entry is made here, please make a simultaneous
 * entry in smtp_reply_map */
enum SMTPCode {
    SMTP_REPLY_211,
    SMTP_REPLY_214,
    SMTP_REPLY_220,
    SMTP_REPLY_221,
    SMTP_REPLY_235,
    SMTP_REPLY_250,
    SMTP_REPLY_251,
    SMTP_REPLY_252,

    SMTP_REPLY_334,
    SMTP_REPLY_354,

    SMTP_REPLY_421,
    SMTP_REPLY_450,
    SMTP_REPLY_451,
    SMTP_REPLY_452,
    SMTP_REPLY_455,

    SMTP_REPLY_500,
    SMTP_REPLY_501,
    SMTP_REPLY_502,
    SMTP_REPLY_503,
    SMTP_REPLY_504,
    SMTP_REPLY_550,
    SMTP_REPLY_551,
    SMTP_REPLY_552,
    SMTP_REPLY_553,
    SMTP_REPLY_554,
    SMTP_REPLY_555,
};

pub fn smtp_decode_event(t: u8) -> String {
    match t {
        SMTP_DECODER_EVENT_INVALID_REPLY => "INVALID_REPLY",
        SMTP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST => "UNABLE_TO_MATCH_REPLY_WITH_REQUEST",
        SMTP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED => "MAX_COMMAND_LINE_LEN_EXCEEDED",
        SMTP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED => "MAX_REPLY_LINE_LEN_EXCEEDED",
        SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE => "INVALID_PIPELINED_SEQUENCE",
        SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED => "BDAT_CHUNK_LEN_EXCEEDED",
        SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE => "NO_SERVER_WELCOME_MESSAGE",
        SMTP_DECODER_EVENT_TLS_REJECTED => "TLS_REJECTED",
        SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED => "DATA_COMMAND_REJECTED",

        /* MIME Events */
        SMTP_DECODER_EVENT_MIME_PARSE_FAILED => "MIME_PARSE_FAILED",
        SMTP_DECODER_EVENT_MIME_MALFORMED_MSG => "MIME_MALFORMED_MSG",
        SMTP_DECODER_EVENT_MIME_INVALID_BASE64 => "MIME_INVALID_BASE64",
        SMTP_DECODER_EVENT_MIME_INVALID_QP => "MIME_INVALID_QP",
        SMTP_DECODER_EVENT_MIME_LONG_LINE => "MIME_LONG_LINE",
        SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE => "MIME_LONG_ENC_LINE",
        SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME => "MIME_LONG_HEADER_NAME",
        SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE => "MIME_LONG_HEADER_VALUE",
        SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG => "MIME_LONG_BOUNDARY",
        SMTP_DECODER_EVENT_MIME_LONG_FILENAME => "MIME_LONG_FILENAME",

        /* Invalid behavior or content */
        SMTP_DECODER_EVENT_DUPLICATE_FIELDS => "DUPLICATE_FIELDS",
        SMTP_DECODER_EVENT_UNPARSABLE_CONTENT => "UNPARSABLE_CONTENT",
        _ => {
            return (t).to_string();
        }
    }
    .to_string()
}

pub smtp_reply(t: u8) -> String {
    match t {
        SMTP_REPLY_211 => "211",
        SMTP_REPLY_214 => "214",
        SMTP_REPLY_220 => "220",
        SMTP_REPLY_221 => "221",
        SMTP_REPLY_235 => "235",
        SMTP_REPLY_250 => "250",
        SMTP_REPLY_251 => "251",
        SMTP_REPLY_252 => "252",

        SMTP_REPLY_334 => "334",
        SMTP_REPLY_354 => "354",

        SMTP_REPLY_421 => "421",
        SMTP_REPLY_450 => "450",
        SMTP_REPLY_451 => "451",
        SMTP_REPLY_452 => "452",
        SMTP_REPLY_455 => "455",

        SMTP_REPLY_500 => "500",
        SMTP_REPLY_501 => "501",
        SMTP_REPLY_502 => "502",
        SMTP_REPLY_503 => "503",
        SMTP_REPLY_504 => "504",
        SMTP_REPLY_550 => "550",
        SMTP_REPLY_551 => "551",
        SMTP_REPLY_552 => "552",
        SMTP_REPLY_553 => "553",
        SMTP_REPLY_554 => "554",
        SMTP_REPLY_555 => "555",
    }.to_string()
}

pub struct SMTPTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,

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
    mime_config: Option<MimeDecConfig>,
    content_lim: u32,
    content_inspect_min_size: u32,
    content_inspect_window: u32,
    sbcfg: Option<StreamingBufferConfig>,  // TODO figure out implementation of this struct
}

impl SMTPConfig {
    pub fn new() -> SMTPConfig {
        SMTPConfig {
            decode_mime: 0,
            mime_config: None,
            content_lim: 0,
            content_inspect_min_size: 0,
            content_inspect_window: 0,
            sbcfg: None,
        }
    }
}

pub smtp_config = SMTPConfig::new();

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
    current_cmd: u8,
    bdat_chunk_len: u32,
    bdat_chunk_idx: u32,
    cmds: Vec<u8>,
    cmds_buf_len: u16,
    cmds_idx: u16,
    helo: Vec<u8>,
    files_ts: Option<FileContainer>;
    file_track_id: u32,
}

impl SMTPState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            request_gap: false,
            response_gap: false,
            direction: 0,
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
            current_cmd: 0,
            bdat_chunk_len: 0,
            bdat_chunk_idx: 0,
            cmds: Vec::new(),
            cmds_buf_len: 0,
            cmds_idx: 0,
            helo: Vec::new(),
            files_ts: None,
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

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&SMTPTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    pub fn get_cur_tx(&mut self) -> Option<&SMTPTransaction> {
        let tx_id = self.tx_id;
        get_tx(tx_id)
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

    fn set_event(e: u8) {
        if let Some(cur_tx) = self.get_cur_tx() {
            // TODO AppLayerDecoderEventsSetEventRaw(&s->curr_tx->decoder_events, e);
            return;
        }
    }

    fn set_mime_events() {
        if self.get_cur_tx().unwrap().mime_state.msg == None {
            return;
        }
        // Generate decoder events
        // TODO MimeDecEntity *msg = state->curr_tx->mime_state->msg;
        match msg.anomaly_flags {
            ANOM_INVALID_BASE64 => {
                self.set_event(SMTP_DECODER_EVENT_MIME_INVALID_BASE64);
            },
            ANOM_INVALID_QP => {
                self.set_event(SMTP_DECODER_EVENT_MIME_INVALID_QP);
            },
            ANOM_LONG_LINE => {
                self.set_event(SMTP_DECODER_EVENT_MIME_LONG_LINE);
            },
            ANOM_LONG_ENC_LINE => {
                self.set_event(SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE);
            },
            ANOM_LONG_HEADER_NAME => {
                self.set_event(SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME);
            },
            ANOM_LONG_HEADER_VALUE => {
                self.set_event(SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE);
            },
            ANOM_MALFORMED_MSG => {
                self.set_event(SMTP_DECODER_EVENT_MIME_MALFORMED_MSG);
            },
            ANOM_LONG_BOUNDARY => {
                self.set_event(SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG);
            },
            ANOM_LONG_FILENAME => {
                self.set_event(SMTP_DECODER_EVENT_MIME_LONG_FILENAME);
            },
            _ => {

            }
        }
    }

    fn get_line(&mut self, input: &[u8]) -> i8 {
        match self.direction {
            core::STREAM_TOSERVER => {
                if self.ts_current_line_lf_seen == 1 {
                    // We have seen the LF for previous line. Clear the parser details 
                    // to parse new line
                    self.ts_current_line_lf_seen = 0;
                    if self.ts_current_line_db == 1 {
                        self.ts_current_line_db = 0;
                        self.current_line = Vec::new(); // TODO is this the right way to free a vector?
                    }
                }
                let lf_idx = input.iter().position(|&x| x == 0x0a);
                match lf_idx {
                    Some(idx) => {
                        self.ts_current_line_lf_seen = 1;
                        if self.ts_current_line_db == 1 {
                            // TODO realloc stuff see if affects in rust
                            self.ts_db.append(input);
                            let ts_len = self.ts_db.len();
                            if ts_len > 1 && self.ts_db[ts_len - 2] == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.current_line = self.ts_db.clone();
                        } else {
                            self.current_line = self.input;
                            // TODO check current_line_len stuff
                            if self.input != idx && idx - 1 == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.input = self.input[idx + 1];
                        }
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
                            self.ts_db.append(input);   
                        } else {
                            self.ts_db.append(input);
                        }
                        // input should probably be zero
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
                        self.current_line = Vec::new(); // TODO is this the right way to free a vector?
                    }
                }
                let lf_idx = input.iter().position(|&x| x == 0x0a);
                match lf_idx {
                    Some(idx) => {
                        self.tc_current_line_lf_seen = 1;
                        if self.tc_current_line_db == 1 {
                            // TODO realloc stuff see if affectc in rust
                            self.tc_db.append(input);
                            let tc_len = self.tc_db.len();
                            if tc_len > 1 && self.tc_db[tc_len - 2] == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.current_line = self.tc_db.clone();
                        } else {
                            self.current_line = self.input;
                            // TODO check current_line_len stuff
                            if self.input != idx && idx - 1 == 0x0D {
                                self.current_line_delim_len = 2;
                            } else {
                                self.current_line_delim_len = 1;
                            }
                            self.input = self.input[idx + 1];
                        }
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
                            self.tc_db.append(input);   
                        } else {
                            self.tc_db.append(input);
                        }
                        // input should probably be zero
                        return -1;
                    }
                }
            },
        }
    }

    fn process_cmd_starttls() -> i8 {
        0
    }

    pub fn process_data_chunk(chunk: u8, len: u32) -> i8 {
        let ret = MIME_DEC_OK;
        // TODO lots of filecontainer stuff here
        let files: FileContainer;

        // FInd mime header and if found set begin to 1 and end to 0

        // TODO see if this unsafe block can be brought out of state impl
        let flags = unsafe { FileFlowToFlags(flow, STREAM_TOSERVER) };
        // we depend on detection engine for file pruning
        flags |= FILE_USE_DETECT;

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
        // TODO get mime from chunk
        if mime.get_param("multipart").is_some() {
            if self.files_ts.is_none() {
                self.files_ts = FileContainer::new();
            }
            files = self.files_ts;

        }

    }

    fn insert_cmd_into_buf(cmd: u8) -> i8 {
        if self.cmds.len() >= self.cmds_buf_len {
            let inc = SMTP_COMMAND_BUFFER_STEPS;
            if self.cmds_buf_len + SMTP_COMMAND_BUFFER_STEPS > u8::MAX {
                inc = u8::MAX - self.cmds_buf_len;
            }
            self.cmds_buf_len += inc;
        }
        if self.cmds.len() >= 1 && (self.cmds.last() == SMTP_COMMAND_STARTTLS || self.cmds.last() == SMTP_COMMAND_DATA) {
            // decoder event
            self.set_event(SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE);
            /* we have to have EHLO, DATA, VRFY, EXPN, TURN, QUIT, NOOP,
            * STARTTLS as the last command in pipelined mode */
        }

        // there's a todo in C code here, ask about it
        if self.cmds.len() + 1 > USHRT_MAX {
            return -1;
        }
        self.cmds.push(cmd);
        0
    }

    fn process_cmd_data() -> i8 {
        if !(self.parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE) {
            /* looks like are still waiting for a confirmation from the server */
            return 0;
        }
        if self.current_line_len == 1 && self.current_line[0] == '.' {
            self.parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            /* kinda like a hack.  The mail sent in DATA mode, would be
            * acknowledged with a reply.  We insert a dummy command to
            * the command buffer to be used by the reply handler to match
            * the reply received */
            self.insert_cmd_into_buf(SMTP_COMMAND_DATA_MODE); // TODO impl this function
            if smtp_config.raw_extraction {
                /* we use this as the signal that message data is complete. */
                // TODO FileCloseFile(state->files_ts, NULL, 0, 0);
            } else if smtp_config.decode_mime && self.get_cur_tx().unwrap().mime_state != NULL { // TODO global smtp_config + mime_State
                // Complete parsing task
                // TODO let ret  = MimeDecParseComplete(state->curr_tx->mime_state);
                if ret != MIME_DEC_OK {
                    self.set_event(SMTP_DECODER_EVENT_MIME_PARSE_FAILED);
                }
                // Generate decoder events
                // TODO SetMimeEvents(state);
            }
            // TODO SMTPTransactionComplete(state)
        } else if smtp_config.raw_extraction {
            // message not over, store the line. This is a substitution of
            // ProcessDataChunk
            // TODO FileAppendData(state->files_ts, state->current_line,
            //    state->current_line_len+state->current_line_delimiter_len);
        }
        // If DATA, parse out a MIME message
        if self.current_cmd == SMTP_COMMAND_DATA && (self.parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE) {
            if smtp_config.decode_mime && self.get_cur_tx().unwrap().mime_state != NULL { // TODO global var smtp_config and mime_state
                // TODO int ret = MimeDecParseLine((const uint8_t *) state->current_line,
                //    state->current_line_len, state->current_line_delimiter_len,
                //    state->curr_tx->mime_state);
                if ret != MIME_DEC_OK {
                    if ret != MIME_DEC_ERR_STATE {
                        // Generate decoder events
                        // TODO SetMimeEvents(state);
                        self.set_event(SMTP_DECODER_EVENT_MIME_PARSE_FAILED);
                    }
                    /* keep the parser in its error state so we can log that,
                    * the parser will reject new data */
                }
            }
        }
    }

    fn process_cmd_bdat(&mut self) -> i8 {
        self.bdat_chunk_idx += self.current_line_len + self.current_line_delim_len;
        if self.bdat_chunk_idx > self.bdat_chunk_len {
            self.parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            // decoder event
            self.set_event(SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED);
            return -1;
        } else if self.bdat_chunk_idx == self.bdat_chunk_len {
            self.parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        }
        0
    }

    fn parse_cmd_bdat(&mut self) -> i8 {
        let i = self.current_line.iter().position(|&x| x != ' '); // TODO recheck this
        if i == 4 || i == self.current_line_len {
            // decoder event
            return -1;
        }
        // TODO find the number in string and convert it to int
        self.bdat_chunk_len = self.current_line[i..];
        // another check for decoder event
        0
    }

    // fn parse_cmd_w_param(&mut self, pref) TODO try to make this into a nom parser

    fn parse_cmd_helo(&mut self) -> i8 {
        let cur_tx = self.get_cur_tx().unwrap();
        if cur_tx.helo {
            self.set_event(SMTP_DECODER_EVENT_DUPLICATE_FIELDS);
            return 0;
        }
        // TODO impl SMTPParseCommandWithParam       
    }

    fn parse_cmd_mail_from(&mut self) -> i8 {
        let cur_tx = self.get_cur_tx().unwrap();
        if cur_tx.mail_from {
            self.set_event(SMTP_DECODER_EVENT_DUPLICATE_FIELDS);
            return 0;
        }
        // TODO impl SMTPParseCommandWithParam
    }  

    fn parse_cmd_rcpt_to(&mut self) -> i8 {
        // TODO impl SMTPParseCommandWithParam
        match res {
            Some(rcpt) => {
                let cur_tx = self.get_cur_tx().unwrap();
                cur_tx.rcpt_to.push(rcpt);
            },
            None => {
                return -1;
            }
        }
        // all goes well
        return 0;
    }

    fn no_new_tx(&mut self) -> i8 {
        if !(self.parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE) {
            if self.current_line_len >= 4 {
                if self.current_line.matches("rset") || self.current_line.matches("quit") {
                    return 1;
                }
            }
        }
        return 0;
    }

    fn process_request(&mut self) -> i8 {//, applayerparserstate?)
        let tx_id = self.tx_id;
        let cur_tx = self.get_tx(tx_id);
        match cur_tx {
            Some(tx) => {
                if tx.done == true && !self.no_new_tx() {
                    let new_tx = self.new_tx();
                }
                // TODO this seems like we'll be creating two transactions with the same tx_id, check this again
                self.transactions.push(new_tx);
                let ts_dcount = self.ts_data_cnt;
                self.ts_last_data_stamp = ts_dcount;
                // TODO StreamTcpReassemblySetMinInspectDepth stuff
                let ts_dcount = self.current_line_len + self.current_line_delim_len;
                let cur_line_lc = self.current_line.to_lowercase();
                if !(self.parser_state & SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
                    self.set_event(SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE); // TODO impl set_event fn
                }
                 /* there are 2 commands that can push it into this COMMAND_DATA mode - STARTTLS and DATA */
                if !(self.parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE) {// TODO add tis macro
                    // TODO design: maybe cur_line_lc switch would make more sense
                    if self.current_line_len >= 8 && cur_line_lc.matches("starttls") {
                        self.current_cmd = SMTP_COMMAND_STARTTLS;
                    } else if self.current_line_len >=4 && cur_line_lc.matches("data") {
                        self.current_cmd = SMTP_COMMAND_DATA;
                        if smtp_config.raw_extraction { // TODO Figure how to work wit a global
                            let msgname = "rawmsg";
                            if self.files_ts == None {
                                self.files_ts = FileContainer::default();
                            }
                            if self.transactions.len() > 1 && !tx.done {
                                self.set_event(SMTP_DECODER_EVENT_UNPARSABLE_CONTENT);
                                FileContainer::file_close();  // TODO figure out FileCloseFile without a track id
                                let new_tx = self.new_tx();
                                self.transactions.push(new_tx);
                            }
                            if FileContainer::file_open() { // TODO figure out this operation
                                self.new_file(); // TODO Implement this function
                            }
                        } else if smtp_config.decode_mime { // TODO figure out globals
                            if tx.mime_state { // TODO check how mime crate fits in here
                                tx.mime_state.state_flag = PARSE_ERROR; // TODO mime and macro
                                self.set_event(SMTP_DECODER_EVENT_UNPARSABLE_CONTENT);
                                let new_tx =self.new_tx();
                                self.transactions.push(new_tx);
                            }
                            // TODO init mime decoder parser

                            // Add new MIME message to end of the list
                            if tx.msg_head == NULL {
                                tx.msg_head = tx.mime_state.msg; // TODO mime crate stuff
                                tx.msg_tail = tx.mime_state.msg; // TODO mime crate stuff
                            } else {
                                tx.msg_tail.next = tx.mime_state.msg;
                                tx.msg_tail = tx.mime_state.msg; //TODO what does this even mean
                            }
                        }
                        /* Enter immediately data mode without waiting for server reply */
                        if self.parser_state & SMTP_PARSER_STATE_PIPELINING_SERVER {
                            self.parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
                        }
                    } else if self.current_line_len >= 4 && cur_line_lc.matches("bdat") {
                        // TODO add SMTPParseCommandBDAT
                        self.current_cmd = SMTP_COMMAND_BDAT;
                        self.parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
                    } else if self.current_line_len >= 4 && (cur_line_lc.matches("helo") || cur_line_lc.matches("ehlo")) {
                        if self.parse_cmd_helo() == -1 {
                            return -1;
                        }
                        self.current_cmd = SMTP_COMMAND_OTHER_CMD;
                    } else if self.current_line_len >= 9 && cur_line_lc.matches("mail from") {
                        if self.parse_cmd_mail_from() == -1 {
                            return -1;
                        }
                        self.current_cmd = SMTP_COMMAND_OTHER_CMD;
                    } else if self.current_line_len >= 7 && cur_line_lc.matches("rcpt to") {
                        if self.parse_cmd_rcpt_to() == -1 {
                            return -1;
                        }
                        self.current_cmd = SMTP_COMMAND_OTHER_CMD;
                    } else if self.current_line_len >= 4 && cur_line_lc.matches("rset") {
                        // Resets chunk index in case of connection reuse
                        self.bdat_chunk_idx = 0;
                        self.current_cmd = SMTP_COMMAND_RSET;
                    } else {
                        self.current_cmd = SMTP_COMMAND_OTHER_CMD;
                    }
                    /* Every command is inserted into a command buffer, to be matched
                    * against reply(ies) sent by the server */
                    self.insert_cmd_into_buf(self.current_cmd);
                    return 0;
                }
                match self.current_cmd {
                    SMTP_COMMAND_STARTTLS => {
                        self.process_cmd_starttls();
                    },
                    SMTP_COMMAND_DATA => {
                        self.process_cmd_data();
                    },
                    SMTP_COMMAND_BDAT => {
                        self.process_cmd_bdat();
                    }
                    _ => {
                        /* we have nothing to do with any other command at this instant.
                        * Just let it go through */
                        return 0;
                    }
                }
            },
            None => {
                let new_tx = self.new_tx();
                // TODO this seems like we'll be creating two transactions with the same tx_id, check this again
                self.transactions.push(new_tx);
                let ts_dcount = self.ts_data_cnt;
                self.ts_last_data_stamp = ts_dcount;
                // TODO StreamTcpReassemblySetMinInspectDepth stuff
                // TODO add everything from Some block here too, maybe make a function
            },
        }
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
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

        let mut start = input;
        while start.len() > 0 {
            match parser::parse_message(start) {  // This is for header parsing etc
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request: {}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    self.transactions.push(tx);
                },
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                },
                Err(_) => {
                    return AppLayerResult::err();
                },
            }
        }

        // Implement SMTPGetLine here somwhere

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while start.len() > 0 {
            match parser::parse_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    match self.find_request() {
                        Some(tx) => {
                            tx.response = Some(response);
                            SCLogNotice!("Found response for request:");
                            SCLogNotice!("- Request: {:?}", tx.request);
                            SCLogNotice!("- Response: {:?}", tx.response);
                        }
                        None => {}
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&SMTPTransaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

fn smtp_configure() {
    let conf = ConfNode::get_child_value("app-layer.protocols.smtp.mime");
    match conf {
        Some(val) => {
            let bool_config_keys = vec!["decode-mime", "decode-base64", "decode-quoted-printable", "extract-urls", "body-md5"];
            for i in bool_config_keys.iter() {}
            // TODO maybe dict way like below won't work, will have to make a struct
                smtp_config[i] = ConfNode::get_child_bool(i); // TODO global smtp_config
            }
            smtp_config["header-value-depth"] = ConfNode::get_child_bool("header-value-depth")
        },
        None => {}
    }

    // TODO Pass mime config data to MimeDec API
    // MimeDecSetConfig(&smtp_config.mime_config);
    smtp_config.content_limit = FILEDATA_CONTENT_LIMIT;
    smtp_config.content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW;
    smtp_config.content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE;

    // TODO child value maybe incorrect here, check again
    let conf = ConfNode::get_child_value("app-layer.protocols.smtp.inspected-tracker");
    match conf {
        Some(val) => {
            // TODO loop over the child keys and get values
            // leaving todo to confirm if child value fn does the right thing
        },
        None => {}
    }
    smtp_config.sbcfg.buf_size = content_limit ? content_limit : 256;
    if ConfNode::get_child_bool("app-layer.protocols.smtp.raw-extraction") != true {
        smtp_config.raw_extraction = SMTP_RAW_EXTRACTION_DEFAULT_VALUE;
    }
    if smtp_config.raw_extraction && smtp_config.decode_mime {
        smtp_config.raw_extraction = 0;
    }
    0
}

/// TODO Probe for a valid header.
///
/// As this smtp protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let size = std::cmp::min(10, input.len());
    let (rem, prefix) = nom::bytes::complete::take(size)(input)?;
    nom::sequence::terminated(
        nom::bytes::complete::take_while1(nom::character::is_digit),
        nom::bytes::complete::tag(":"),
    )(prefix)?;
    Ok((rem, ()))
}

// C exports.

export_tx_get_detect_state!(
    rs_smtp_tx_get_detect_state,
    SMTPTransaction
);
export_tx_set_detect_state!(
    rs_smtp_tx_set_detect_state,
    SMTPTransaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_smtp_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return unsafe { ALPROTO_SMTP };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = SMTPState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<SMTPState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, SMTPState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_smtp_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };

    if eof {
        // If needed, handled EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, SMTPState);

    if input == std::ptr::null_mut() && input_len > 0 {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(input_len);
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_request(buf)
    }
}

#[no_mangle]
pub extern "C" fn rs_smtp_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> AppLayerResult {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, SMTPState);

    if input == std::ptr::null_mut() && input_len > 0 {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(input_len);
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_response(buf).into()
    }
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, SMTPState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, SMTPState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_progress_completion_status(
    _direction: u8,
) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_smtp_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, SMTPTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_get_events(
    tx: *mut std::os::raw::c_void
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, SMTPTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_smtp_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
                                                         _event_name: *mut *const std::os::raw::c_char,
                                                         _event_type: *mut core::AppLayerEventType
) -> i8 {
    return -1;
}
#[no_mangle]
pub extern "C" fn rs_smtp_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, SMTPState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(
                c_tx,
                out_tx_id,
                has_next,
            );
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub extern "C" fn rs_smtp_get_request_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, SMTPTransaction);
    if let Some(ref request) = tx.request {
        if request.len() > 0 {
            unsafe {
                *len = request.len() as u32;
                *buf = request.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub extern "C" fn rs_smtp_get_response_buffer(
    tx: *mut std::os::raw::c_void,
    buf: *mut *const u8,
    len: *mut u32,
) -> u8
{
    let tx = cast_pointer!(tx, SMTPTransaction);
    if let Some(ref response) = tx.response {
        if response.len() > 0 {
            unsafe {
                *len = response.len() as u32;
                *buf = response.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

export_tx_data_get!(rs_smtp_get_tx_data, SMTPTransaction);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"smtp-rust\0";

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_register_parser() {
    let default_port = CString::new("[7000]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_smtp_probing_parser),
        probe_tc: Some(rs_smtp_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_smtp_state_new,
        state_free: rs_smtp_state_free,
        tx_free: rs_smtp_state_tx_free,
        parse_ts: rs_smtp_parse_request,
        parse_tc: rs_smtp_parse_response,
        get_tx_count: rs_smtp_state_get_tx_count,
        get_tx: rs_smtp_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_smtp_tx_get_alstate_progress,
        get_de_state: rs_smtp_tx_get_detect_state,
        set_de_state: rs_smtp_tx_set_detect_state,
        get_events: Some(rs_smtp_state_get_events),
        get_eventinfo: Some(rs_smtp_state_get_event_info),
        get_eventinfo_byid : Some(rs_smtp_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_smtp_state_get_tx_iterator),
        get_tx_data: rs_smtp_get_tx_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SMTP = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust smtp parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for SMTP.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe() {
        assert!(probe(b"1").is_err());
        assert!(probe(b"1:").is_ok());
        assert!(probe(b"123456789:").is_ok());
        assert!(probe(b"0123456789:").is_err());
    }

    #[test]
    fn test_incomplete() {
        let mut state = SMTPState::new();
        let buf = b"5:Hello3:bye";

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 2});

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 0, needed: 3});

        // This is the first message and only the first message.
        let r = state.parse_request(&buf[0..7]);
        assert_eq!(r, AppLayerResult{ status: 0, consumed: 0, needed: 0});

        // The first message and a portion of the second.
        let r = state.parse_request(&buf[0..9]);
        assert_eq!(r, AppLayerResult{ status: 1, consumed: 7, needed: 3});
    }
}
