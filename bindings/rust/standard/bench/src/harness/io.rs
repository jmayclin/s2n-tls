// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    any::Any, cell::RefCell, collections::VecDeque, fmt::Debug, io::ErrorKind, pin::Pin, rc::Rc,
};

use super::Mode;

pub type LocalDataBuffer = RefCell<VecDeque<u8>>;

pub struct TestPairIO {
    /// a data buffer that the server writes to and the client reads from
    pub server_tx_stream: Pin<Rc<LocalDataBuffer>>,
    /// a data buffer that the client writes to and the server reads from
    pub client_tx_stream: Pin<Rc<LocalDataBuffer>>,
    /// The transcript is a record of all writes that were made by each peer. This
    /// can be useful when verifying record sizing logic.
    pub transcript: Option<Rc<RefCell<Vec<(Mode, Vec<u8>)>>>>,

    pub associated_storage: Vec<Box<dyn Any>>,
}

impl Default for TestPairIO {
    fn default() -> Self {
        Self {
            server_tx_stream: Rc::pin(Default::default()),
            client_tx_stream: Rc::pin(Default::default()),
            transcript: None,
            associated_storage: Vec::new(),
        }
    }
}

impl Debug for TestPairIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestPairIO")
            .field("server_tx_stream", &self.server_tx_stream.borrow().len())
            .field("client_tx_stream", &self.client_tx_stream.borrow().len())
            .finish()
    }
}

impl TestPairIO {
    pub fn new_with_recording() -> Self {
        let mut pair = Self::default();
        pair.transcript = Some(Rc::new(RefCell::new(Vec::new())));
        pair
    }

    pub fn total_bytes_sent(&self, peer: Mode) -> usize {
        self.writes(peer).iter().map(|message| message.len()).sum()
    }

    /// get the writes that `peer` has made from the transcript
    pub fn writes(&self, peer: Mode) -> Vec<Vec<u8>> {
        assert!(self.transcript.is_some());
        self.transcript
            .as_ref()
            .unwrap()
            .borrow()
            .iter()
            .filter_map(|(writing_peer, bytes)| {
                if *writing_peer == peer {
                    Some(bytes.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn client_view(&self) -> ViewIO {
        ViewIO {
            view_owner: Mode::Client,
            send_ctx: self.client_tx_stream.clone(),
            recv_ctx: self.server_tx_stream.clone(),
            transcript_handle: self.transcript.clone(),
        }
    }

    pub fn server_view(&self) -> ViewIO {
        ViewIO {
            view_owner: Mode::Server,
            send_ctx: self.server_tx_stream.clone(),
            recv_ctx: self.client_tx_stream.clone(),
            transcript_handle: self.transcript.clone(),
        }
    }
}

/// A "view" of the IO.
///
/// This view is client/server specific, and notably implements the read and write
/// traits.
///
// This struct is used by Openssl and Rustls which both rely on a "stream" abstraction
// which implements read and write. This is not used by s2n-tls, which relies on
// lower level callbacks.
#[derive(Debug)]
pub struct ViewIO {
    pub view_owner: Mode,
    pub send_ctx: Pin<Rc<LocalDataBuffer>>,
    pub recv_ctx: Pin<Rc<LocalDataBuffer>>,
    transcript_handle: Option<Rc<RefCell<Vec<(Mode, Vec<u8>)>>>>,
}

// I am lying here
unsafe impl Send for ViewIO {}
unsafe impl Sync for ViewIO {}

impl std::io::Read for ViewIO {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.recv_ctx.borrow_mut().read(buf);
        if let Ok(0) = res {
            // We are "faking" a TcpStream, where a read of length 0 indicates
            // EoF. That is incorrect for this scenario. Instead we return WouldBlock
            // to indicate that there is simply no more data to be read.
            Err(std::io::Error::new(ErrorKind::WouldBlock, "blocking"))
        } else {
            res
        }
    }
}

impl std::io::Write for ViewIO {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(transcript) = &self.transcript_handle {
            transcript
                .borrow_mut()
                .push((self.view_owner, Vec::from(buf)));
        }
        self.send_ctx.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
