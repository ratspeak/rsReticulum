//! Runtime wiring for the path table and traffic filters: the config
//! directory's list files, per-interface hop limits and filter registrations.
use super::*;

#[test]
fn config_dir_type_lists_fill_the_filter_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("known_destination_types"),
        "# known\nlxmf.delivery\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("flagged_destination_types"), "spam.type\n").unwrap();
    let mut rc = ReticulumConfig::default();
    load_config_dir_lists(dir.path(), &mut rc);
    assert_eq!(rc.filter.known_types, ["lxmf.delivery"]);
    assert_eq!(rc.filter.flagged_types, ["spam.type"]);

    let empty = tempfile::tempdir().unwrap();
    let mut rc = ReticulumConfig::default();
    load_config_dir_lists(empty.path(), &mut rc);
    assert!(rc.filter.known_types.is_empty() && rc.filter.flagged_types.is_empty());
}
