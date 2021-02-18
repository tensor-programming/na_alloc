use crate::types::*;

use std::{
    cell::Cell,
    fmt::{self, Debug},
    mem,
    ptr::NonNull,
    slice, thread,
};

use libsodium_sys::{
    sodium_allocarray, sodium_free, sodium_init, sodium_mprotect_noaccess,
    sodium_mprotect_readonly, sodium_mprotect_readwrite,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prot {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

type RefCount = u8;

pub(crate) struct Box<T: Bytes> {
    ptr: NonNull<T>,
    len: usize,
    prot: Cell<Prot>,
    refs: Cell<RefCount>,
}

impl<T: Bytes> Box<T> {
    pub(crate) fn new<F>(len: usize, init: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        let mut boxed = Self::new_unlocked(len);

        assert!(
            boxed.ptr != std::ptr::NonNull::dangling(),
            "Make sure pointer isn't dangling"
        );
        assert!(boxed.len == len);

        init(&mut boxed);

        boxed.lock();

        boxed
    }

    pub(crate) fn try_new<R, E, F>(len: usize, init: F) -> Result<Self, E>
    where
        F: FnOnce(&mut Self) -> Result<R, E>,
    {
        let mut boxed = Self::new_unlocked(len);

        assert!(
            boxed.ptr != std::ptr::NonNull::dangling(),
            "Make sure pointer isn't dangling"
        );
        assert!(boxed.len == len);

        let res = init(&mut boxed);

        boxed.lock();

        res.map(|_| boxed)
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn size(&self) -> usize {
        self.len * T::size()
    }

    pub(crate) fn unlock(&self) -> &Self {
        self.retain(Prot::ReadOnly);
        self
    }

    pub(crate) fn unlock_mut(&mut self) -> &mut Self {
        self.retain(Prot::ReadWrite);
        self
    }

    pub(crate) fn lock(&self) {
        self.release()
    }

    pub(crate) fn as_ref(&self) -> &T {
        assert!(
            !self.is_empty(),
            "Attempted to dereference a zero-length pointer"
        );

        assert!(
            self.prot.get() != Prot::NoAccess,
            "May not call box while locked"
        );

        unsafe { self.ptr.as_ref() }
    }

    pub(crate) fn as_mut(&mut self) -> &mut T {
        assert!(
            !self.is_empty(),
            "Attempted to dereference a zero-length pointer"
        );

        assert!(
            self.prot.get() == Prot::ReadWrite,
            "May not call box unless mutably unlocked"
        );

        unsafe { self.ptr.as_mut() }
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        assert!(
            self.prot.get() != Prot::NoAccess,
            "May not call box while locked"
        );

        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        assert!(
            self.prot.get() == Prot::ReadWrite,
            "secrets: may not call Box::as_mut_slice unless mutably unlocked"
        );

        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    fn new_unlocked(len: usize) -> Self {
        if unsafe { sodium_init() == -1 } {
            panic!("Failed to initialize libsodium")
        }

        let ptr = NonNull::new(unsafe { sodium_allocarray(len, mem::size_of::<T>()) as *mut _ })
            .expect("Failed to allocate memory");

        Self {
            ptr,
            len,
            prot: Cell::new(Prot::ReadWrite),
            refs: Cell::new(1),
        }
    }

    fn retain(&self, prot: Prot) {
        let refs = self.refs.get();

        if refs == 0 {
            assert!(prot != Prot::NoAccess, "Must retain readably or writably");

            self.prot.set(prot);
            mprotect(self.ptr.as_ptr(), prot);
        } else {
            assert!(
                Prot::NoAccess != self.prot.get(),
                "Out-of-order retain/release detected"
            );
            assert!(
                Prot::ReadWrite != self.prot.get(),
                "Cannot unlock mutably more than once"
            );
            assert!(
                Prot::ReadOnly == prot,
                "Cannot unlock mutably while unlocked immutably"
            );
        }

        match refs.checked_add(1) {
            Some(v) => self.refs.set(v),
            None if self.is_locked() => panic!("secrets: out-of-order retain/release detected"),
            None => panic!("secrets: retained too many times"),
        };
    }

    fn release(&self) {
        assert!(self.refs.get() != 0, "Releases exceeded retains");

        assert!(
            self.prot.get() != Prot::NoAccess,
            "Releasing memory that's already locked"
        );

        let refs = self.refs.get().wrapping_sub(1);

        self.refs.set(refs);

        if refs == 0 {
            mprotect(self.ptr.as_ptr(), Prot::NoAccess);
            self.prot.set(Prot::NoAccess);
        }
    }

    fn is_locked(&self) -> bool {
        self.prot.get() == Prot::NoAccess
    }
}

impl<T: Bytes + Randomized> Box<T> {
    pub(crate) fn random(len: usize) -> Self {
        Self::new(len, |b| b.as_mut_slice().randomize())
    }
}

impl<T: Bytes + ZeroOut> Box<T> {
    pub(crate) fn zero(len: usize) -> Self {
        Self::new(len, |b| b.as_mut_slice().zero())
    }
}

impl<T: Bytes> Drop for Box<T> {
    fn drop(&mut self) {
        if !thread::panicking() {
            assert!(self.refs.get() == 0, "secrets: retains exceeded releases");

            assert!(
                self.prot.get() == Prot::NoAccess,
                "secrets: dropped secret was still accessible"
            );
        }

        unsafe { free(self.ptr.as_mut()) }
    }
}

impl<T: Bytes> Debug for Box<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{{ {} bytes redacted }}", self.size())
    }
}

impl<T: Bytes> Clone for Box<T> {
    fn clone(&self) -> Self {
        Self::new(self.len, |b| {
            b.as_mut_slice().copy_from_slice(self.unlock().as_slice());
            self.lock();
        })
    }
}

impl<T: Bytes + ConstEq> PartialEq for Box<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let lhs = self.unlock().as_slice();
        let rhs = other.unlock().as_slice();

        let ret = lhs.const_eq(rhs);

        self.lock();
        other.lock();

        ret
    }
}

impl<T: Bytes + ZeroOut> From<&mut T> for Box<T> {
    fn from(data: &mut T) -> Self {
        Self::new(1, |b| unsafe { data.copy_and_zero(b.as_mut()) })
    }
}

impl<T: Bytes + ZeroOut> From<&mut [T]> for Box<T> {
    fn from(data: &mut [T]) -> Self {
        Self::new(data.len(), |b| unsafe {
            data.copy_and_zero(b.as_mut_slice())
        })
    }
}

unsafe impl<T: Bytes + Send> Send for Box<T> {}

fn mprotect<T>(ptr: *mut T, prot: Prot) {
    if !match prot {
        Prot::NoAccess => unsafe { sodium_mprotect_noaccess(ptr as *mut _) == 0 },
        Prot::ReadOnly => unsafe { sodium_mprotect_readonly(ptr as *mut _) == 0 },
        Prot::ReadWrite => unsafe { sodium_mprotect_readwrite(ptr as *mut _) == 0 },
    } {
        panic!("Error setting memory protection to {:?}", prot);
    }
}

pub(crate) unsafe fn free<T>(ptr: *mut T) {
    sodium_free(ptr as *mut _)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::process;

    #[test]
    fn test_init_with_garbage() {
        let boxed = Box::<u8>::new(4, |_| {});
        let unboxed = boxed.unlock().as_slice();

        let garbage = unsafe {
            let garb_ptr = sodium_allocarray(1, mem::size_of::<u8>()) as *mut u8;
            let garb_byte = *garb_ptr;

            free(garb_ptr);

            vec![garb_byte; unboxed.len()]
        };

        assert_ne!(garbage, vec![0; garbage.len()]);
        assert_eq!(unboxed, &garbage[..]);

        boxed.lock();
    }

    #[test]
    fn test_custom_init() {
        let boxed = Box::<u8>::new(1, |secret| {
            secret.as_mut_slice().clone_from_slice(b"\x04");
        });

        assert_eq!(boxed.unlock().as_slice(), [0x04]);
        boxed.lock();
    }
}
