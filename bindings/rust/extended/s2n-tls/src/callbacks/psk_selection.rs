// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::identity,
    marker::PhantomData,
    ops::Deref,
    ptr::{self, NonNull},
};

use s2n_tls_sys::*;

use crate::{
    connection::Connection,
    error::Fallible,
    foreign_types::{Opaque, S2NRef},
};

struct OfferedPsk<'wire_input> {
    ptr: NonNull<s2n_offered_psk>,
    // The `&[u8]` returned from `OfferedPsk::identity` is now owned by the OfferedPsk
    // struct, but instead is a direct reference to the "wire-data" owned by the
    // s2n-tls connection.
    wire_input: PhantomData<&'wire_input [u8]>,
}

impl<'wire_input> OfferedPsk<'wire_input> {
    fn allocate() -> Result<Self, crate::error::Error> {
        let ptr = unsafe { s2n_offered_psk_new().into_result() }?;
        Ok(Self {
            ptr,
            wire_input: PhantomData,
        })
    }

    pub fn identity(&self) -> Result<&'wire_input [u8], crate::error::Error> {
        let mut identity_buffer = ptr::null_mut::<u8>();
        let mut size = 0;
        unsafe {
            s2n_offered_psk_get_identity(self.ptr.as_ptr(), &mut identity_buffer, &mut size)
                .into_result()?
        };

        Ok(unsafe {
            // SAFETY: valid, aligned, non-null -> If the s2n-tls API didn't fail
            //         (which we check for) then data will be non-null, valid for
            //         reads, and aligned.
            // SAFETY: the memory is not mutated -> For the life of the PSK Selection
            //         callback, nothing else is mutating the wire buffer which
            //         is the backing memory of the identities.
            std::slice::from_raw_parts(identity_buffer, size as usize)
        })
    }
}

impl<'wire_input> Drop for OfferedPsk<'wire_input> {
    fn drop(&mut self) {
        let mut s2n_ptr = self.ptr.as_ptr();
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_offered_psk_free(std::ptr::addr_of_mut!(s2n_ptr)).into_result() };
    }
}

struct OfferedPskListRef<'wire_input> {
    _ptr: Opaque,
    // When `OfferedPskListRef::next` is called, the "wire-data" owned by the
    // s2n-tls connection is parsed.
    buffer: PhantomData<&'wire_input [u8]>,
}

impl<'callback> S2NRef for OfferedPskListRef<'callback> {
    type ForeignType = s2n_offered_psk_list;
}

impl<'wire_input> OfferedPskListRef<'wire_input> {
    fn has_next(&self) -> bool {
        // SAFETY: *mut cast - s2n-tls does not treat the pointer as mutable.
        unsafe { s2n_offered_psk_list_has_next(self.as_s2n_ptr() as *mut _) }
    }

    fn next(&mut self, psk: &mut OfferedPsk) -> Result<(), crate::error::Error> {
        let psk_ptr = psk.ptr.as_ptr();
        unsafe { s2n_offered_psk_list_next(self.as_s2n_ptr_mut(), psk_ptr).into_result() }?;
        Ok(())
    }

    fn choose_psk(&mut self, psk: &OfferedPsk) -> Result<(), crate::error::Error> {
        let mut_psk = psk.ptr.as_ptr();
        unsafe { s2n_offered_psk_list_choose_psk(self.as_s2n_ptr_mut(), mut_psk).into_result()? };
        Ok(())
    }

    fn reread(&mut self) -> Result<(), crate::error::Error> {
        unsafe { s2n_offered_psk_list_reread(self.as_s2n_ptr_mut()).into_result() }?;
        Ok(())
    }
}

/// A struct used to select a PSK from a list of offered PSKs.
// Implementing this as a "cursor" allows us to use a single allocation for many
// PSKs. Implementing this as a list/iterator would require an allocation for
// each offered PSK.
pub struct OfferedPskCursor<'callback> {
    psk: OfferedPsk<'callback>,
    list: &'callback mut OfferedPskListRef<'callback>,
}

impl<'callback> Iterator for OfferedPskCursor<'callback> {
    type Item = Result<&'callback [u8], crate::error::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.list.has_next() {
            if let Err(e) = self.list.next(&mut self.psk) {
                return Some(Err(e));
            }
            Some(self.psk.identity())
        } else {
            None
        }
    }
}

impl<'callback> OfferedPskCursor<'callback> {
    pub(crate) fn new(list: *mut s2n_offered_psk_list) -> Result<Self, crate::error::Error> {
        let list = OfferedPskListRef::from_s2n_ptr_mut(list);
        let psk = OfferedPsk::allocate()?;
        Ok(Self { psk, list })
    }

    /// Choose the currently selected PSK to negotiate with.
    ///
    /// If no offered PSK is acceptable, implementors can return from the callback
    /// without calling this function to reject the connection.
    pub fn choose_current_psk(&mut self) -> Result<(), crate::error::Error> {
        self.list.choose_psk(&self.psk)
    }

    /// Reset the cursor, allowing the list to be reread.
    pub fn rewind(&mut self) -> Result<(), crate::error::Error> {
        self.list.reread()?;
        Ok(())
    }
}

/// A trait used by the server to select an external PSK given a client's offered
/// list of external PSK identities.
///
/// If working with small numbers of PSKs, consider just directly using [Connection::append_psk].
///
/// Used in conjunction with [crate::config::Builder::set_psk_selection_callback].
pub trait PskSelectionCallback: 'static + Send + Sync {
    /// Select a psk using the [OfferedPskCursor].
    ///
    /// Before calling [OfferedPskCursor::choose_current_psk], implementors must
    /// first append the corresponding [crate::external_psk::ExternalPsk] to the
    /// connection using [Connection::append_psk].
    fn select_psk(&self, connection: &mut Connection, psk_cursor: &mut OfferedPskCursor);
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            atomic::{self, AtomicBool},
            Arc,
        },
    };

    use crate::error::Error as S2NError;

    use crate::{
        config::Config,
        error::{ErrorSource, ErrorType},
        external_psk::ExternalPsk,
        security::DEFAULT_TLS13,
        testing::TestPair,
    };

    use super::*;

    fn test_psk(id: u8) -> Result<(Identity, ExternalPsk), crate::error::Error> {
        let identity = vec![id];
        let mut psk = ExternalPsk::builder()?;
        psk.with_identity(&identity)?
            .with_secret(&[id + 1; 16])?
            .with_hmac(crate::enums::PskHmac::SHA384)?;
        Ok((identity, psk.build()?))
    }

    type Identity = Vec<u8>;

    #[derive(Clone)]
    struct PskStore {
        store: Arc<HashMap<Identity, ExternalPsk>>,
        invoked: Arc<AtomicBool>,
    }

    impl PskStore {
        const SIZE: u8 = 200;

        fn new() -> Result<Self, S2NError> {
            let mut store = HashMap::new();
            for i in 0..Self::SIZE {
                let (identity, psk) = test_psk(i)?;
                store.insert(identity, psk);
            }
            Ok(Self {
                store: Arc::new(store),
                invoked: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    impl PskSelectionCallback for PskStore {
        fn select_psk(&self, connection: &mut Connection, psk_cursor: &mut OfferedPskCursor) {
            self.invoked.store(true, atomic::Ordering::Relaxed);

            let identities: Vec<&[u8]> = psk_cursor.map(|psk| psk.unwrap()).collect();

            // check that the identities were successfully read
            for (i, identity) in identities.iter().enumerate() {
                assert_eq!(&[i as u8], *identity);
            }

            // after resetting the cursor, we should observe all of the same identities
            psk_cursor.rewind().unwrap();
            let identities_again: Vec<&[u8]> = psk_cursor.map(|psk| psk.unwrap()).collect();

            assert_eq!(identities.len(), Self::SIZE as usize);
            assert_eq!(identities, identities_again);

            psk_cursor.rewind().unwrap();
            let chosen = psk_cursor.next().unwrap().unwrap();
            let chosen_external = self.store.get(chosen).unwrap();
            connection.append_psk(chosen_external).unwrap();
            psk_cursor.choose_current_psk().unwrap();
        }
    }

    #[test]
    fn psk_handshake_with_callback() -> Result<(), S2NError> {
        let psk_store = PskStore::new()?;
        let client_psks = psk_store.clone();

        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.set_psk_selection_callback(psk_store)?;

        let config = config.build()?;
        let mut test_pair = TestPair::from_config(&config);
        // append in sorted order to make assertions easier
        for id in 0..PskStore::SIZE {
            test_pair
                .client
                .append_psk(client_psks.store.get(&vec![id]).unwrap())?;
        }
        assert!(test_pair.handshake().is_ok());
        assert!(client_psks.invoked.load(atomic::Ordering::Relaxed));
        Ok(())
    }

    #[derive(Clone)]
    struct ImmediateSelect(Arc<AtomicBool>);

    impl PskSelectionCallback for ImmediateSelect {
        fn select_psk(&self, _connection: &mut Connection, psk_cursor: &mut OfferedPskCursor) {
            self.0.store(true, atomic::Ordering::Relaxed);
            let err = psk_cursor.choose_current_psk().unwrap_err();
            assert_eq!(err.kind(), ErrorType::InternalError);
            assert_eq!(err.source(), ErrorSource::Library);
        }
    }

    #[test]
    // If choose_current_psk is called when there isn't a current psk, s2n-tls
    // should return a well formed error.
    fn choose_empty_psk() -> Result<(), crate::error::Error> {
        let selector = ImmediateSelect(Arc::new(AtomicBool::new(false)));
        let selector_handle = selector.clone();
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.set_psk_selection_callback(selector)?;

        let mut test_pair = TestPair::from_config(&config.build()?);
        test_pair.client.append_psk(&test_psk(1).unwrap().1)?;
        assert!(test_pair.handshake().is_err());
        assert!(selector_handle.0.load(atomic::Ordering::Relaxed));
        Ok(())
    }

    #[derive(Clone)]
    struct NeverSelect(Arc<AtomicBool>);

    impl PskSelectionCallback for NeverSelect {
        fn select_psk(&self, _connection: &mut Connection, _psk_cursor: &mut OfferedPskCursor) {
            self.0.store(true, atomic::Ordering::Relaxed);
            // return without calling cursor.choose_current_psk
        }
    }

    #[test]
    // If choose_current_psk isn't called, then the handshake should fail gracefully.
    fn no_chosen_psk() -> Result<(), crate::error::Error> {
        let selector = NeverSelect(Arc::new(AtomicBool::new(false)));
        let selector_handle = selector.clone();
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.set_psk_selection_callback(selector)?;

        let mut test_pair = TestPair::from_config(&config.build()?);
        test_pair.client.append_psk(&test_psk(1).unwrap().1)?;
        let err = test_pair.handshake().unwrap_err();
        assert_eq!(err.kind(), ErrorType::ProtocolError);
        assert_eq!(err.source(), ErrorSource::Library);
        assert!(selector_handle.0.load(atomic::Ordering::Relaxed));
        Ok(())
    }
}
