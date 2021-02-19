use crate::{boxed::Boxed, types::*};

use std::{
    fmt::{self, Debug, Formatter},
    ops::{Deref, DerefMut},
};

#[derive(Clone, Eq)]
pub struct Guarded<T: Bytes> {
    boxed: Boxed<T>,
}

pub struct Ref<'a, T: Bytes> {
    boxed: &'a Boxed<T>,
}

pub struct RefMut<'a, T: Bytes> {
    boxed: &'a mut Boxed<T>,
}

impl<T: Bytes> Guarded<T> {
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        Self {
            boxed: Boxed::new(1, |b| f(b.as_mut())),
        }
    }

    pub fn try_new<R, E, F>(f: F) -> Result<Self, E>
    where
        F: FnOnce(&mut T) -> Result<R, E>,
    {
        Boxed::try_new(1, |b| f(b.as_mut())).map(|b| Self { boxed: b })
    }

    pub fn size(&self) -> usize {
        self.boxed.size()
    }

    pub fn borrow(&self) -> Ref<'_, T> {
        Ref::new(&self.boxed)
    }

    pub fn borrow_mut(&mut self) -> RefMut<'_, T> {
        RefMut::new(&mut self.boxed)
    }
}

impl<'a, T: Bytes> Ref<'a, T> {
    fn new(boxed: &'a Boxed<T>) -> Self {
        assert!(
            boxed.len() == 1,
            "Attempted to dereference a box with zero length"
        );

        Self {
            boxed: boxed.unlock(),
        }
    }
}

impl<T: Bytes> PartialEq for Ref<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<RefMut<'_, T>> for Ref<'_, T> {
    fn eq(&self, rhs: &RefMut<'_, T>) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> Eq for Ref<'_, T> {}

impl<'a, T: Bytes> RefMut<'a, T> {
    /// Instantiates a new `RefMut`.
    fn new(boxed: &'a mut Boxed<T>) -> Self {
        assert!(
            boxed.len() == 1,
            "Attempted to dereference a boxed with zero length"
        );

        Self {
            boxed: boxed.unlock_mut(),
        }
    }
}

impl<T: Bytes> Clone for Ref<'_, T> {
    fn clone(&self) -> Self {
        Self {
            boxed: self.boxed.unlock(),
        }
    }
}

impl<T: Bytes> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: Bytes> Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for RefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.boxed.as_ref()
    }
}

impl<T: Bytes> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.boxed.as_mut()
    }
}

impl<T: Bytes> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes + Randomized> Guarded<T> {
    pub fn random() -> Self {
        Self {
            boxed: Boxed::random(1),
        }
    }
}

impl<T: Bytes + ZeroOut> Guarded<T> {
    pub fn zero() -> Self {
        Self {
            boxed: Boxed::zero(1),
        }
    }
}

impl<T: Bytes + ZeroOut> From<&mut T> for Guarded<T> {
    fn from(data: &mut T) -> Self {
        Self { boxed: data.into() }
    }
}

impl<T: Bytes> Debug for Guarded<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes + ConstEq> PartialEq for Guarded<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.boxed.eq(&rhs.boxed)
    }
}

impl<T: Bytes> PartialEq for RefMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<Ref<'_, T>> for RefMut<'_, T> {
    fn eq(&self, rhs: &Ref<'_, T>) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> Eq for RefMut<'_, T> {}
