//! Owned Objective-C values for the Apple BLE modules. Their calls run on Tokio
//! workers and other threads with no autorelease pool, where an autoreleased
//! object lives until the thread exits.

use objc2::msg_send;
use objc2::rc::{Allocated, Retained};
use objc2::runtime::{AnyClass, AnyObject};
use objc2_foundation::NSString;
use uuid::Uuid;

/// `UUIDWithString:` autoreleases, so call this inside `autoreleasepool`.
pub(crate) fn cbuuid(uuid: &Uuid) -> Retained<AnyObject> {
    let s = NSString::from_str(&uuid.to_string());
    let cls = AnyClass::get(c"CBUUID").expect("CBUUID must exist at runtime");
    unsafe { msg_send![cls, UUIDWithString: &*s] }
}

/// A copy of `bytes`, never autoreleased.
pub(crate) fn nsdata(bytes: &[u8]) -> Retained<AnyObject> {
    let cls = AnyClass::get(c"NSData").expect("NSData must exist at runtime");
    unsafe {
        let obj: Allocated<AnyObject> = msg_send![cls, alloc];
        msg_send![obj,
            initWithBytes: bytes.as_ptr().cast::<std::ffi::c_void>(),
            length: bytes.len()]
    }
}

/// Never autoreleased; the array retains each element.
pub(crate) fn nsarray(objects: &[&AnyObject]) -> Retained<AnyObject> {
    let cls = AnyClass::get(c"NSArray").expect("NSArray must exist at runtime");
    let ptrs: Vec<*const AnyObject> = objects.iter().map(|o| *o as *const AnyObject).collect();
    unsafe {
        let obj: Allocated<AnyObject> = msg_send![cls, alloc];
        msg_send![obj, initWithObjects: ptrs.as_ptr(), count: ptrs.len()]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use objc2::rc::{Weak, autoreleasepool};

    /// Runs `make` on a thread with no autorelease pool, drops what it returns,
    /// and reports whether every returned object was freed. A stray retain or
    /// an autorelease outside `make`'s own pool keeps the object alive.
    pub(crate) fn freed_on_drop<F>(make: F) -> bool
    where
        F: FnOnce() -> Vec<Retained<AnyObject>> + Send + 'static,
    {
        std::thread::spawn(move || {
            let weak: Vec<Weak<AnyObject>> = {
                let objs = make();
                let weak: Vec<_> = objs.iter().map(Weak::from_retained).collect();
                // A class without weak-reference support would pass vacuously.
                assert!(weak.iter().all(|w| w.load().is_some()));
                weak
            };
            weak.iter().all(|w| w.load().is_none())
        })
        .join()
        .expect("probe thread")
    }

    #[test]
    fn probe_sees_an_autoreleased_object() {
        assert!(!freed_on_drop(|| {
            let cls = AnyClass::get(c"NSData").unwrap();
            let bytes = [0xCDu8; 300];
            unsafe {
                let raw: *mut AnyObject = msg_send![cls,
                    dataWithBytes: bytes.as_ptr().cast::<std::ffi::c_void>(),
                    length: bytes.len()];
                vec![Retained::retain(raw).unwrap()]
            }
        }));
    }

    #[test]
    fn nsdata_and_nsarray_are_never_autoreleased() {
        assert!(freed_on_drop(|| {
            let data = nsdata(&[0xAB; 300]);
            let arr = nsarray(&[&data]);
            vec![data, arr]
        }));
    }

    #[test]
    fn cbuuid_holds_no_extra_retain() {
        assert!(freed_on_drop(|| {
            autoreleasepool(|_| vec![cbuuid(&crate::ble_peer::RATSPEAK_SERVICE_UUID)])
        }));
    }
}
