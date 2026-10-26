//! Versioned, exact-length wire encoding. All integers are little endian.
//! No wire field in an ordinary request can establish caller identity or authority.

use airlock_clipboard_core::{Chunk, Error, Request, Response};
use xen_transport::{Error as TransportError, Kind, MAX_PAYLOAD, Wire};

/// Untrusted data-plane request with a versioned wire representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation(
    /// Clipboard operation without caller identity or authorization assertions.
    pub Request,
);

impl Wire for Operation {
    const KIND: Kind = Kind::Request;

    fn encode(&self, out: &mut [u8; MAX_PAYLOAD]) -> Result<usize, TransportError> {
        let (tag, transfer, value, data) = match &self.0 {
            Request::Copy { transfer, size } => (1, transfer, *size, None),
            Request::Write {
                transfer,
                offset,
                data,
            } => (2, transfer, *offset, Some(data)),
            Request::Complete { transfer } => (3, transfer, 0, None),
            Request::Paste { transfer } => (4, transfer, 0, None),
            Request::Read { transfer, offset } => (5, transfer, *offset, None),
            Request::Cancel { transfer } => (6, transfer, 0, None),
        };
        let value = u32::try_from(value).map_err(|_| TransportError::TooLarge)?;
        out[..2].copy_from_slice(&[1, tag]);
        out[2..10].copy_from_slice(&transfer.to_le_bytes());
        out[10..14].copy_from_slice(&value.to_le_bytes());
        let bytes = data.map(Chunk::bytes).unwrap_or_default();
        out[14..14 + bytes.len()].copy_from_slice(bytes);
        Ok(14 + bytes.len())
    }

    fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < 14 || bytes[0] != 1 {
            return Err(TransportError::Malformed);
        }
        let transfer = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        let value = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
        if bytes[1] != 2 && bytes.len() != 14 {
            return Err(TransportError::Malformed);
        }
        if matches!(bytes[1], 3 | 4 | 6) && value != 0 {
            return Err(TransportError::Malformed);
        }

        Ok(Self(match bytes[1] {
            1 => Request::Copy {
                transfer,
                size: value,
            },
            2 => Request::Write {
                transfer,
                offset: value,
                data: Chunk::new(&bytes[14..]).map_err(|_| TransportError::Malformed)?,
            },
            3 => Request::Complete { transfer },
            4 => Request::Paste { transfer },
            5 => Request::Read {
                transfer,
                offset: value,
            },
            6 => Request::Cancel { transfer },
            _ => return Err(TransportError::Malformed),
        }))
    }
}

/// Bounded reply; Debug reveals only lengths and error categories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply(
    /// Policy result, independent of transport delivery errors.
    pub Result<Response, Error>,
);

impl Wire for Reply {
    const KIND: Kind = Kind::Response;

    fn encode(&self, out: &mut [u8; MAX_PAYLOAD]) -> Result<usize, TransportError> {
        out[0] = 1;
        match &self.0 {
            Ok(Response::Ok) => {
                out[1] = 0;
                Ok(2)
            }
            Ok(Response::Size(size)) => {
                out[1] = 1;
                out[2..6].copy_from_slice(&(*size as u32).to_le_bytes());
                Ok(6)
            }
            Ok(Response::Data(data)) => {
                out[1] = 2;
                out[2..2 + data.bytes().len()].copy_from_slice(data.bytes());
                Ok(2 + data.bytes().len())
            }
            Err(error) => {
                out[1..3].copy_from_slice(&[3, *error as u8]);
                Ok(3)
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < 2 || bytes[0] != 1 {
            return Err(TransportError::Malformed);
        }
        Ok(Self(match (bytes[1], bytes.len()) {
            (0, 2) => Ok(Response::Ok),
            (1, 6) => Ok(Response::Size(
                u32::from_le_bytes(bytes[2..6].try_into().unwrap()) as usize,
            )),
            (2, _) => Ok(Response::Data(
                Chunk::new(&bytes[2..]).map_err(|_| TransportError::Malformed)?,
            )),
            (3, 3) => Err(match bytes[2] {
                1 => Error::Unauthorized,
                2 => Error::Replay,
                3 => Error::Unavailable,
                4 => Error::Bounds,
                5 => Error::Busy,
                6 => Error::Order,
                7 => Error::Clock,
                8 => Error::Malformed,
                _ => return Err(TransportError::Malformed),
            }),
            _ => return Err(TransportError::Malformed),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_frame_lengths_and_bounded_data() {
        let request = Operation(Request::Write {
            transfer: 9,
            offset: 192,
            data: Chunk::new(&[17; 192]).unwrap(),
        });
        let mut bytes = [0; MAX_PAYLOAD];
        let len = request.encode(&mut bytes).unwrap();
        assert!(len <= MAX_PAYLOAD);
        assert_eq!(Operation::decode(&bytes[..len]).unwrap(), request);
        for len in 0..14 {
            assert!(Operation::decode(&bytes[..len]).is_err());
        }
        assert!(Operation::decode(&bytes).is_err());
        for tag in [0, 7, 255] {
            bytes[1] = tag;
            assert!(Operation::decode(&bytes[..14]).is_err());
        }
    }

    #[test]
    fn response_roundtrip_and_invalid_error() {
        for result in [
            Ok(Response::Ok),
            Ok(Response::Size(65_536)),
            Ok(Response::Data(Chunk::new(b"private").unwrap())),
            Err(Error::Unauthorized),
            Err(Error::Clock),
        ] {
            let reply = Reply(result);
            let mut bytes = [0; MAX_PAYLOAD];
            let len = reply.encode(&mut bytes).unwrap();
            assert_eq!(Reply::decode(&bytes[..len]).unwrap(), reply);
        }
        assert!(Reply::decode(&[1, 3, 99]).is_err());
        assert!(Reply::decode(&[1, 0, 0]).is_err());
    }
}
