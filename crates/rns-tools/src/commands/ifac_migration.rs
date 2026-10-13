//! Explicit offline IFAC unit migration. Output never includes raw config.
use rns_runtime::config::ifac::{IfacMigrationPlan, IfacSourceUnits, plan_ifac_unit_migration};
use rns_runtime::config::ifac_lock::ConfigWriteLock;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

#[derive(clap::Subcommand)]
pub(super) enum Command {
    /// Inspect or migrate configuration without starting networking.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}
#[derive(clap::Subcommand)]
pub(super) enum ConfigCommand {
    /// Preview or publish an explicit IFAC size unit conversion while writers are stopped.
    IfacUnits {
        /// Exact interface name; repeat to select multiple interfaces.
        #[arg(long = "interface", required = true)]
        interfaces: Vec<String>,
        /// Interpret the selected unmarked sizes using their known original units.
        #[arg(long = "source-units", value_enum)]
        units: Units,
        /// Publish the previewed conversion with a private immutable backup.
        #[arg(long = "write")]
        apply: bool,
    },
}
#[derive(Clone, Copy, clap::ValueEnum)]
pub(super) enum Units {
    Bytes,
    Bits,
}
impl Command {
    pub(super) fn run(&self, directory: &Path) -> Result<(), String> {
        let Self::Config {
            command:
                ConfigCommand::IfacUnits {
                    interfaces,
                    units,
                    apply,
                },
        } = self;
        let path = directory.join("config");
        let source =
            fs::read_to_string(&path).map_err(|error| format!("cannot read config: {error}"))?;
        let units = match units {
            Units::Bytes => IfacSourceUnits::Bytes,
            Units::Bits => IfacSourceUnits::Bits,
        };
        let plan = plan_ifac_unit_migration(&source, interfaces, units)
            .map_err(|error| error.to_string())?;
        println!("Source: {}", hex::encode(plan.source_hash()));
        for change in plan.changes() {
            println!(
                "{}: ifac_size -> {} bits ({} bytes), ifac_size_unit = bits",
                change.interface,
                change.effective_bytes * 8,
                change.effective_bytes
            );
        }
        if plan.is_unchanged() {
            println!("No changes required.");
            return Ok(());
        }
        if !apply {
            println!(
                "Preview only. Stop external config writers and repeat with --write to publish."
            );
            return Ok(());
        }
        let backup = publish(&path, &source, &plan)?;
        println!(
            "IFAC units migrated. Private rollback backup: {}",
            backup.display()
        );
        println!("Restore this backup before using a pre-migration Rust binary.");
        Ok(())
    }
}

fn publish(path: &Path, source: &str, plan: &IfacMigrationPlan) -> Result<PathBuf, String> {
    let _lock =
        ConfigWriteLock::acquire(path).map_err(|error| format!("cannot lock config: {error}"))?;
    let current =
        fs::read_to_string(path).map_err(|error| format!("cannot reread config: {error}"))?;
    if !plan.source_matches(&current) || current != source {
        return Err("config changed since the snapshot; nothing was rewritten".into());
    }
    rns_runtime::config::ifac::validate_ifac_update(Some(source), plan.proposed_config())
        .map_err(|error| format!("candidate config rejected: {error}"))?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock predates epoch")?
        .as_nanos();
    let backup = parent.join(format!("config.ifac-backup-{}-{nonce}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let reservation = options
        .open(&backup)
        .map_err(|error| format!("cannot reserve private backup: {error}"))?;
    drop(reservation);
    rns_identity::persistence::durable_write(&backup, source.as_bytes())
        .map_err(|error| format!("backup publication failed ({error}); preserve recovery files"))?;
    // Check again immediately before publication; cooperating writers hold the
    // same lock, and an external edit observed here must never be overwritten.
    let current =
        fs::read_to_string(path).map_err(|error| format!("cannot reread config: {error}"))?;
    if !plan.source_matches(&current) {
        return Err("config changed before publication; private backup retained".into());
    }
    rns_identity::persistence::durable_write(path,plan.proposed_config().as_bytes()).map_err(|error|format!("config publication failed ({error}); preserve private backup and reconcile before restarting"))?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = "[interfaces]\n[[radio]]\ntype = TCPClientInterface\ntarget_host = example.invalid\ntarget_port = 4242\nnetworkname = private-net\nifac_size = 16\n";
    #[test]
    fn migration_publication_has_immutable_backup_and_source_cas() {
        let dir = std::env::temp_dir().join(format!(
            "ifac-cli-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config");
        fs::write(&path, SOURCE).unwrap();
        let plan =
            plan_ifac_unit_migration(SOURCE, &["radio".into()], IfacSourceUnits::Bytes).unwrap();
        fs::write(&path, format!("{SOURCE}# changed\n")).unwrap();
        assert!(publish(&path, SOURCE, &plan).is_err());
        assert!(fs::read_to_string(&path).unwrap().ends_with("# changed\n"));
        fs::write(&path, SOURCE).unwrap();
        let backup = publish(&path, SOURCE, &plan).unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), SOURCE);
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("ifac_size = 128")
        );
        let migrated = fs::read_to_string(&path).unwrap();
        assert!(
            plan_ifac_unit_migration(&migrated, &["radio".into()], IfacSourceUnits::Bytes)
                .unwrap()
                .is_unchanged()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
