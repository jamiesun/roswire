use super::sentence::{parse_api_sentence, read_sentence, write_sentence, SentenceKind};
use super::transport::ApiStream;
use crate::error::{RosWireError, RosWireResult};
use md5::{Digest, Md5};

enum LoginOutcome {
    Authenticated,
    Challenge(Vec<u8>),
}

/// Logs in over the RouterOS native API, transparently handling both the
/// modern (RouterOS 6.43+/v7) and legacy (pre-6.43) login flows.
///
/// RouterOS 6.43+ accepts the username and password in the first `/login`
/// sentence and replies `!done`. Pre-6.43 firmware ignores the supplied
/// password and instead replies `!done` with a `=ret=<challenge>` attribute;
/// in that case we complete the MD5 challenge-response handshake.
pub fn login<S: ApiStream + ?Sized>(
    stream: &mut S,
    user: &str,
    password: &str,
) -> RosWireResult<()> {
    write_sentence(
        stream,
        &[
            "/login".to_owned(),
            format!("=name={user}"),
            format!("=password={password}"),
        ],
    )?;

    match read_login_outcome(stream)? {
        LoginOutcome::Authenticated => Ok(()),
        LoginOutcome::Challenge(challenge) => {
            let response = v6_challenge_response(password, &challenge);
            write_sentence(
                stream,
                &[
                    "/login".to_owned(),
                    format!("=name={user}"),
                    format!("=response=00{response}"),
                ],
            )?;
            read_login_completion(stream)
        }
    }
}

pub fn v6_challenge_response(password: &str, challenge: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update([0]);
    hasher.update(password.as_bytes());
    hasher.update(challenge);
    encode_hex(&hasher.finalize())
}

fn read_login_outcome<S: ApiStream + ?Sized>(stream: &mut S) -> RosWireResult<LoginOutcome> {
    loop {
        let words = read_sentence(stream)?;
        let sentence = parse_api_sentence(&words)?;
        match sentence.kind {
            SentenceKind::Done => {
                return match sentence.attributes.get("ret") {
                    Some(ret) => Ok(LoginOutcome::Challenge(decode_hex(ret)?)),
                    None => Ok(LoginOutcome::Authenticated),
                };
            }
            SentenceKind::Trap | SentenceKind::Fatal => {
                return Err(Box::new(RosWireError::auth_failed(
                    sentence
                        .attributes
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| "RouterOS authentication failed".to_owned()),
                )));
            }
            SentenceKind::Re | SentenceKind::Empty | SentenceKind::Other(_) => continue,
        }
    }
}

fn read_login_completion<S: ApiStream + ?Sized>(stream: &mut S) -> RosWireResult<()> {
    loop {
        let words = read_sentence(stream)?;
        let sentence = parse_api_sentence(&words)?;
        match sentence.kind {
            SentenceKind::Done => return Ok(()),
            SentenceKind::Trap | SentenceKind::Fatal => {
                return Err(Box::new(RosWireError::auth_failed(
                    sentence
                        .attributes
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| "RouterOS authentication failed".to_owned()),
                )));
            }
            SentenceKind::Re | SentenceKind::Empty | SentenceKind::Other(_) => continue,
        }
    }
}

fn decode_hex(value: &str) -> RosWireResult<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(Box::new(RosWireError::ros_api_failure(
            "RouterOS v6 login challenge has an odd hex length",
        )));
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(value: u8) -> RosWireResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(Box::new(RosWireError::ros_api_failure(
            "RouterOS v6 login challenge contains non-hex data",
        ))),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0F) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{login, v6_challenge_response};
    use crate::error::ErrorCode;
    use crate::protocol::classic::sentence::{read_sentence, write_sentence};
    use std::io::{Cursor, Read, Result, Write};

    struct FakeApiStream {
        rx: Cursor<Vec<u8>>,
        tx: Vec<u8>,
    }

    impl FakeApiStream {
        fn with_sentences(sentences: &[Vec<String>]) -> Self {
            let mut rx = Vec::new();
            for sentence in sentences {
                write_sentence(&mut rx, sentence).expect("fixture sentence should encode");
            }
            Self {
                rx: Cursor::new(rx),
                tx: Vec::new(),
            }
        }

        fn written_sentences(&self) -> Vec<Vec<String>> {
            let mut cursor = Cursor::new(self.tx.clone());
            let mut sentences = Vec::new();
            while (cursor.position() as usize) < cursor.get_ref().len() {
                sentences.push(read_sentence(&mut cursor).expect("written sentence should decode"));
            }
            sentences
        }
    }

    impl Read for FakeApiStream {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
            self.rx.read(buffer)
        }
    }

    impl Write for FakeApiStream {
        fn write(&mut self, buffer: &[u8]) -> Result<usize> {
            self.tx.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn modern_login_writes_credentials_and_accepts_done() {
        let mut stream = FakeApiStream::with_sentences(&[vec!["!done".to_owned()]]);
        let credential = test_credential();

        login(&mut stream, "admin", &credential).expect("login should succeed");

        assert_eq!(
            stream.written_sentences(),
            vec![vec![
                "/login".to_owned(),
                "=name=admin".to_owned(),
                format!("=password={credential}"),
            ]],
        );
    }

    #[test]
    fn login_trap_maps_to_auth_failed() {
        let mut stream = FakeApiStream::with_sentences(&[vec![
            "!trap".to_owned(),
            "=message=invalid user name or password".to_owned(),
        ]]);
        let mut invalid_credential = test_credential();
        invalid_credential.push('x');

        let error =
            login(&mut stream, "admin", &invalid_credential).expect_err("login should fail");

        assert_eq!(error.error_code, ErrorCode::AuthFailed);
        assert_eq!(error.message, "invalid user name or password");
    }

    #[test]
    fn legacy_login_completes_challenge_when_done_includes_ret() {
        let challenge = "01020304";
        let credential = test_credential();
        let expected = v6_challenge_response(&credential, &[1, 2, 3, 4]);
        let mut stream = FakeApiStream::with_sentences(&[
            vec!["!done".to_owned(), format!("=ret={challenge}")],
            vec!["!done".to_owned()],
        ]);

        login(&mut stream, "admin", &credential).expect("legacy login should succeed");

        assert_eq!(
            stream.written_sentences(),
            vec![
                vec![
                    "/login".to_owned(),
                    "=name=admin".to_owned(),
                    format!("=password={credential}"),
                ],
                vec![
                    "/login".to_owned(),
                    "=name=admin".to_owned(),
                    format!("=response=00{expected}"),
                ],
            ],
        );
    }

    #[test]
    fn legacy_login_challenge_failure_maps_to_auth_failed() {
        let credential = test_credential();
        let mut stream = FakeApiStream::with_sentences(&[
            vec!["!done".to_owned(), "=ret=01020304".to_owned()],
            vec![
                "!trap".to_owned(),
                "=message=invalid user name or password".to_owned(),
            ],
        ]);

        let error = login(&mut stream, "admin", &credential).expect_err("login should fail");

        assert_eq!(error.error_code, ErrorCode::AuthFailed);
    }

    fn test_credential() -> String {
        ['t', 'e', 's', 't', '-', 'v', 'a', 'l', 'u', 'e']
            .iter()
            .collect()
    }
}
