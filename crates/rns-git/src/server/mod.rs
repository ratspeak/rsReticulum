//! The rngit repository node (`RNS/Utilities/rngit/server.py@1.6.0`).

pub mod client;
pub mod config;
pub mod forks;
pub mod handlers;
pub mod layout;
pub mod perms;
pub mod perms_mgmt;
pub mod releases;
pub mod stats;
pub mod work;

/// `APP_NAME` plus the aspect (`__init__.py:31`, `server.py:2063`).
pub const APP_NAME: &str = "git.repositories";

pub const PATH_LIST: &str = "/git/list";
pub const PATH_FETCH: &str = "/git/fetch";
pub const PATH_PUSH: &str = "/git/push";
pub const PATH_DELETE: &str = "/git/delete";
pub const PATH_CREATE: &str = "/git/create";
pub const PATH_FORK: &str = "/git/fork";
pub const PATH_SYNC: &str = "/git/sync";
pub const PATH_MIRROR: &str = "/git/mirror";
pub const PATH_RELEASE: &str = "/mgmt/release";
pub const PATH_PERMS: &str = "/mgmt/perms";
pub const PATH_WORK: &str = "/mgmt/work";

pub const RES_OK: u8 = 0x00;
pub const RES_DISALLOWED: u8 = 0x01;
pub const RES_INVALID_REQ: u8 = 0x02;
pub const RES_NOT_FOUND: u8 = 0x03;
pub const RES_REMOTE_FAIL: u8 = 0xFF;

pub const IDX_REPOSITORY: u8 = 0x00;
pub const IDX_RESULT_CODE: u8 = 0x01;
pub const IDX_GROUP: u8 = 0x02;

/// Python `len(s)`: the number of code points.
pub(crate) fn py_len(s: &str) -> usize {
    s.chars().count()
}
