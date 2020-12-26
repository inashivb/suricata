/* Copyright (C) 2018 Open Information Security Foundation
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
use nom::number::streaming::{le_u8};

fn parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

named!(pub parse_message<String>,
       do_parse!(
           len:  map_res!(
                 map_res!(take_until!(":"), std::str::from_utf8), parse_len) >>
           _sep: take!(1) >>
           msg:  take_str!(len) >>
               (
                   msg.to_string()
    )));

#[derive(Debug, PartialEq)]
pub struct DummyState {
    pub val: u8,
    pub val1: u8,
}

impl DummyState {
    pub fn new() -> DummyState {
        DummyState {
            val: 0,
            val1: 0,
        }
    }
}

named!(pub parse_line<DummyState>,
       do_parse!(
           take_till!(|a| a == 0x0a)
           >> i: peek!(bits!(tag_bits!(8usize, 0x0a)))
           >> cond!(i == 0x0a, take!(1))
           >> val: le_u8
           >> val1: le_u8
           >> (
            DummyState {
                val: val,
                val1: val1
            })
    ));

#[cfg(test)]
mod tests {

    use nom::*;
    use super::*;

    #[test]
    fn test_tag_exists() {
        let buf: &[u8] = &[0x12, 0xa1, 0x0a, 0x23, 0xb3,];
        let result  = parse_line(buf);
        match result {
            Ok((rem, ret)) => {
                let expected = DummyState {
                    val: 0x23,
                    val1: 0xb3
                };
                println!("buf: {:?}", buf);
                assert_eq!(ret, expected);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(Err::Failure(err)) => {
                panic!("Result should not be a failure: {:?}.", err);
            }
        }
    }

    fn test_tag_no_exists() {
        let buf: &[u8] = &[0x12, 0xa1, 0x23, 0xb3,];
        let result  = parse_line(buf);
        match result {
            Ok((rem, ret)) => {
                let expected = DummyState {
                    val: 0x23,
                    val1: 0xb3
                };
                println!("buf: {:?}", buf);
                assert_eq!(ret, expected);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
            Err(Err::Failure(err)) => {
                panic!("Result should not be a failure: {:?}.", err);
            }
        }
    }

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        let buf = b"12:Hello World!4:Bye.";

        let result = parse_message(buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message, "Hello World!");

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 6);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) |
            Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

}
