use std::{ops::Deref, ptr::addr_of_mut};

use s2n_tls_sys::*;

use crate::{connection::Connection, error::Fallible, foreign_types::S2NRef};

crate::foreign_types::define_owned_type!(
    /// owned PSK type
    OfferedPsk,
    s2n_offered_psk
);

impl OfferedPsk {
    pub(crate) fn allocate() -> Result<Self, crate::error::Error> {
        let ptr = unsafe { s2n_offered_psk_new().into_result() }?;
        Ok(Self::from_s2n_ptr(ptr))
    }
}

impl Deref for OfferedPsk {
    type Target = OfferedPskRef;

    fn deref(&self) -> &Self::Target {
        OfferedPskRef::from_s2n_ptr(self.as_s2n_ptr())
    }
}

impl Drop for OfferedPsk {
    fn drop(&mut self) {
        let mut s2n_ptr = self.ptr.as_ptr();
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_offered_psk_free(std::ptr::addr_of_mut!(s2n_ptr)).into_result() };
    }
}

crate::foreign_types::define_ref_type!(
    /// a reference to an offered psk.
    OfferedPskRef,
    s2n_offered_psk
);

impl OfferedPskRef {
    pub fn identity(&self) -> Result<&[u8], crate::error::Error> {
        let mut identity_buffer: *mut u8 = std::ptr::null::<u8>() as *mut u8;
        let mut size = 0;
        unsafe {
            s2n_offered_psk_get_identity(
                self.as_s2n_ptr(),
                addr_of_mut!(identity_buffer),
                &mut size,
            )
            .into_result()?
        };
        Ok(unsafe { std::slice::from_raw_parts(identity_buffer, size as usize) })
    }
}

crate::foreign_types::define_ref_type!(
    /// A private type that aliases [s2n_offered_psk_list]. This is used by the
    /// [OfferedPskCursor].
    OfferedPskListRef,
    s2n_offered_psk_list
);

impl OfferedPskListRef {
    fn has_next(&self) -> bool {
        unsafe { s2n_offered_psk_list_has_next(self.as_s2n_ptr()) }
    }

    fn next(&mut self, psk: &mut OfferedPsk) -> Result<(), crate::error::Error> {
        let psk_ptr = psk.as_s2n_ptr() as *mut s2n_offered_psk;
        unsafe { s2n_offered_psk_list_next(self.as_s2n_ptr_mut(), psk_ptr).into_result() }?;
        Ok(())
    }

    fn choose_psk(&mut self, psk: &OfferedPsk) -> Result<(), crate::error::Error> {
        let mut_psk = psk.as_s2n_ptr() as *mut s2n_offered_psk;
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
    psk: OfferedPsk,
    list: &'callback mut OfferedPskListRef,
}

impl<'callback> OfferedPskCursor<'callback> {
    pub(crate) fn new(list: &'callback mut OfferedPskListRef) -> Result<Self, crate::error::Error> {
        let psk = OfferedPsk::allocate()?;
        Ok(Self { psk, list })
    }

    /// Advance the cursor, returning the currently selected PSK.
    pub fn advance(&mut self) -> Result<Option<&OfferedPsk>, crate::error::Error> {
        if !self.list.has_next() {
            Ok(None)
        } else {
            self.list.next(&mut self.psk)?;
            Ok(Some(&self.psk))
        }
    }

    /// Choose the currently selected PSK to negotiate with.
    pub fn choose_current_psk(self) -> Result<(), crate::error::Error> {
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
    fn select_psk(&self, connection: &mut Connection, psk_cursor: OfferedPskCursor);
}