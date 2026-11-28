//! Depth-bounded MessagePack decoding for peer-supplied bytes.

/// rmpv spends two depth units per container level, so this admits 63 nested
/// containers: far deeper than any Reticulum or LXMF structure. rmpv's default
/// (1024) needs over 2 MiB of stack in an unoptimised build.
pub const MAX_DECODE_DEPTH: usize = 128;

/// `rmpv::decode::read_value`, refusing nesting past [`MAX_DECODE_DEPTH`].
pub fn read_value<R: std::io::Read>(rd: &mut R) -> Result<rmpv::Value, rmpv::decode::Error> {
    rmpv::decode::read_value_with_max_depth(rd, MAX_DECODE_DEPTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested(levels: usize) -> Vec<u8> {
        let mut packed = vec![0x91; levels];
        packed.push(0xc0);
        packed
    }

    #[test]
    fn deep_nesting_is_refused_without_recursing_on_the_stack() {
        assert!(read_value(&mut &nested(63)[..]).is_ok());
        assert!(read_value(&mut &nested(64)[..]).is_err());
        // rmpv's default depth overflows this stack in a debug build.
        let deep = nested(100_000);
        let refused = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(move || read_value(&mut &deep[..]).is_err())
            .unwrap()
            .join()
            .unwrap();
        assert!(refused);
    }
}
