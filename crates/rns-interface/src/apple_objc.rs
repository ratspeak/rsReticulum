//! Owned Objective-C values for the Apple BLE modules. Their calls run on Tokio
//! workers and other threads with no autorelease pool, where an autoreleased
//! object lives until the thread exits.

use objc2::msg_send;
use objc2::rc::{Allocated, Retained, autoreleasepool};
use objc2::runtime::{AnyClass, AnyObject};
use objc2_foundation::NSString;
use uuid::Uuid;

/// Runs `f`, returning an Objective-C exception it raises as `Err`. One that
/// reaches Rust aborts the process.
pub(crate) fn catch_objc<R>(what: &str, f: impl FnOnce() -> R) -> Result<R, String> {
    objc2::exception::catch(std::panic::AssertUnwindSafe(f)).map_err(|e| match e {
        Some(e) => format!("{what}: {e}"),
        None => format!("{what}: Objective-C exception"),
    })
}

/// Whether a CoreBluetooth manager may ask for state restoration in `mode`
/// (`bluetooth-central` or `bluetooth-peripheral`). iOS raises for a restore
/// identifier unless the bundle declares the mode, which an app extension
/// cannot.
pub(crate) fn may_restore(mode: &str) -> bool {
    !cfg!(target_os = "ios") || declares_background_mode(mode)
}

/// Whether the main bundle's `UIBackgroundModes` lists `mode`.
pub(crate) fn declares_background_mode(mode: &str) -> bool {
    autoreleasepool(|_| unsafe {
        let (Some(bundle_cls), Some(array_cls)) =
            (AnyClass::get(c"NSBundle"), AnyClass::get(c"NSArray"))
        else {
            return false;
        };
        let bundle: *mut AnyObject = msg_send![bundle_cls, mainBundle];
        if bundle.is_null() {
            return false;
        }
        let key = NSString::from_str("UIBackgroundModes");
        let modes: *mut AnyObject = msg_send![bundle, objectForInfoDictionaryKey: &*key];
        if modes.is_null() {
            return false;
        }
        let is_array: bool = msg_send![modes, isKindOfClass: array_cls];
        let mode = NSString::from_str(mode);
        is_array && msg_send![modes, containsObject: &*mode]
    })
}

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
    use objc2::rc::Weak;

    #[test]
    fn an_objective_c_exception_comes_back_as_an_error() {
        let raised = catch_objc("manager", || unsafe {
            let cls = AnyClass::get(c"NSArray").unwrap();
            let empty: *mut AnyObject = msg_send![cls, array];
            let _: *mut AnyObject = msg_send![empty, objectAtIndex: 3usize];
        });
        let error = raised.unwrap_err();
        assert!(error.starts_with("manager: "), "{error}");
        assert!(error.contains("index 3"), "{error}");
        assert_eq!(catch_objc("manager", || 7), Ok(7));
    }

    /// A test binary declares no background modes, so an iOS one would ask
    /// for no restoration; elsewhere restoration is never refused.
    #[test]
    fn restoration_follows_the_declared_background_modes() {
        assert!(!declares_background_mode("bluetooth-central"));
        assert!(!declares_background_mode("bluetooth-peripheral"));
        assert_eq!(may_restore("bluetooth-central"), !cfg!(target_os = "ios"));
    }

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
