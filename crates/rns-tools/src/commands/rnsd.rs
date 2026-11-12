//! rnsd-rs - Reticulum daemon.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
#[path = "ifac_migration.rs"]
mod ifac_migration;
use tracing_subscriber::fmt::MakeWriter;

use rns_tools::{RETICULUM_COMPAT_VERSION, RS_RETICULUM_VERSION};
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
// Upstream `rnsd --exampleconfig` output, including print()'s trailing newline.
const RNSD_EXAMPLE_CONFIG: &str = r#"# This is an example Reticulum config file.
# You should probably edit it to include any additional,
# interfaces and settings you might need.

[reticulum]

# If you enable Transport, your system will route traffic
# for other peers, pass announces and serve path requests.
# This should be done for systems that are suited to act
# as transport nodes, ie. if they are stationary and
# always-on. This directive is optional and can be removed
# for brevity.

enable_transport = no


# By default, the first program to launch the Reticulum
# Network Stack will create a shared instance, that other
# programs can communicate with. Only the shared instance
# opens all the configured interfaces directly, and other
# local programs communicate with the shared instance over
# a local socket. This is completely transparent to the
# user, and should generally be turned on. This directive
# is optional and can be removed for brevity.

share_instance = yes


# If you want to run multiple *different* shared instances
# on the same system, you will need to specify different
# instance names for each. On platforms supporting domain
# sockets, this can be done with the instance_name option:

instance_name = default


# Some platforms don't support domain sockets, and if that
# is the case, you can isolate different instances by
# specifying a unique set of ports for each:

# shared_instance_port = 37428
# instance_control_port = 37429


# If you want to explicitly use TCP for shared instance
# communication, instead of domain sockets, this is also
# possible, by using the following option:

# shared_instance_type = tcp


# On systems where running instances may not have access
# to the same shared Reticulum configuration directory,
# it is still possible to allow full interactivity for
# running instances, by manually specifying a shared RPC
# key. In almost all cases, this option is not needed, but
# it can be useful on operating systems such as Android.
# The key must be specified as bytes in hexadecimal.

# rpc_key = e5c032d3ec4e64a6aca9927ba8ab73336780f6d71790


# It is possible to allow remote management of Reticulum
# systems using the various built-in utilities, such as
# rnstatus and rnpath. You will need to specify one or
# more Reticulum Identity hashes for authenticating the
# queries from client programs. For this purpose, you can
# use existing identity files, or generate new ones with
# the rnid utility.

# enable_remote_management = yes
# remote_management_allowed = 9fb6d773498fb3feda407ed8ef2c3229, 2d882c5586e548d79b5af27bca1776dc


# For easier management, discovery and configuration of
# networks with many individual transport instances,
# you can specify a network identity to be used across
# a set of instances. If sending interface discovery
# announces, these will all be signed by the specified
# network identity, and other nodes discovering your
# interfaces will be able to identify that they belong
# to the same network, even though they exist on different
# transport nodes.

# network_identity = ~/.reticulum/storage/identity/network


# It is possible to configure the global default interface
# gravity. This value will be used if an interface does
# not have a specific gravity value in its configuration.

# default_gravity = 0

# You can configure whether Reticulum should discover
# available interfaces from other Transport Instances over
# the network. If this option is enabled, Reticulum will
# collect interface information discovered from the network.

# discover_interfaces = no


# If you only want to discover interfaces from specific
# networks, you can provide a list of network identities
# from which to discover interfaces. If this option is not
# provided, interfaces will be discovered from all transport
# instances on all connected networks.

# interface_discovery_sources = 78616ff7c4b8d3886d67d494b440f333, cb127015e13aa6ea1e0a606cdc9123d0


# It is possible to automatically bring up and connect new
# interfaces discovered over the network. This option is
# disabled by default, but allows you to specify a maximum
# number of discovered interfaces to automatically connect.
# Additionally, if this option is enabled, Reticulum will
# also try to autoconnect available auto-discovered inter-
# faces on startup, up to the maximum number specified.

# autoconnect_discovered_interfaces = 0


# To prevent interface discovery spamming, a valid crypto-
# graphic stamp is required per announced interface. You
# can configure the minimum required value to accept as
# valid for discovered interfaces.

# required_discovery_value = 14


# You can disable allowing interfaces to be attached, de-
# tached or reloaded via rnstatus, for example if running
# on a shared system where users with normal RPC access
# should not be allowed to control interface states.

# enable_interface_management = no


# You can configure Reticulum to panic and forcibly close
# if an unrecoverable interface error occurs, such as the
# hardware device for an interface disappearing. This is
# an optional directive, and can be left out for brevity.
# This behaviour is disabled by default.

# panic_on_interface_error = no

# You can specify which mode discovered interfaces should
# be created with when auto-connecting.

# autoconnect_interface_mode = gw


# It is possible to allow announces from auto-connected
# interfaces to propagate announces to internal-mode
# interfaces, even if the auto-connected interface's mode
# would normally not allow for this.

# autoconnect_announces_to_internal = yes


# You can configure the gravity for discovered interfaces
# that are auto-connected.

# autoconnect_interface_gravity = 0


# When Transport is enabled, it is possible to allow the
# Transport Instance to respond to probe requests from
# the rnprobe utility. This can be a useful tool to test
# connectivity. When this option is enabled, the probe
# destination will be generated from the Identity of the
# Transport Instance, and printed to the log at startup.
# Optional, and disabled by default.

# respond_to_probes = no


# You can publish your local list of blackholed identities
# for other transport instances to use for automatic,
# network-wide blackhole management.

# publish_blackhole = no


# List of remote transport identities from which to auto-
# matically source lists of blackholed identities.
#
# If you're connecting to a large external network, you
# can use one or more external blackhole list to block
# spammy and excessive announces onto your network. This
# funtionality is especially useful if you're hosting public
# entrypoints or gateways. The list source below provides a
# functional example, but better, more timely maintained
# lists probably exist in the community.

# blackhole_sources = 521c87a83afb8f29e4455e77930b973b


# You can set the interval in minutes at which remote
# blackhole sources are updated. Defaults to one hour.

# blackhole_update_interval = 60


# You can enable a hop limiter, that will drop all packets
# exceeding the specified maximum hop count.

# hop_limiter = 16


# When not running as a transport node, it is possible to
# force the use of the same, static transport identity
# for every instance start. Defaults to using a new identity
# at every instance start, if transport is disabled.

# static_transport_identity = no

[stamps]
# This section configures stamping behaviour and defaults.
# In most cases, you do not need to change this, but on
# constrained systems especially, tuning these parameters
# can be very beneficial

# During the 1.6.x phased transition to network stamp usage,
# it is possible to enable early opt-in on stamp generation
# and enforcement. RNS 1.6.0 includes all the required stamp
# generation and verification functionality, and actively
# validates stamps, while leaving generation, emission and
# enforcement disabled by default for destinations and PRs.
# Link requests will be stamped already from 1.6.0 if a cost
# has been announced by the destination. Version 1.6.1 will
# enable generation and emission by default, and version
# 1.6.2 will finally activate enforcement. Any of these
# options can be enabled early by configuration:

# stamp_destinations = yes
# stamp_prs = yes
# enforce_stamps = yes


# The default required stamp cost for an announce, and its
# destination to be considered valid. This applies both to
# announces received directly, and transported by this node,
# if transport is enabled. Any announced destination not
# meeting the cost will be ignored.

# destination_cost = 23.5


# The default value this instance will target when generating
# new destination stamps. An application may set a higher
# target, but applications requesting a lower value than the
# default will always generate at least the default value.
# Destination stamps are cached and reused, so a one-time
# high-value generation is usually a good idea.

# destination_value = 25.0


# The default required path request stamp cost. Path requests
# that do not meet the requirement are ignored.

# pr_cost = 15.8


# The default target value of path request stamps generated
# by this instance.

# pr_value = 15.8


# The default link request stamp cost to use, if one has not
# been announced by the destination the link is established
# to, or if it is unknown. In practice, all destinations will
# include their required link cost in each announce, and this
# option is rarely necessary.

# lr_cost = 12.5


# The maximum amount of time to spend attempting to generate
# a link request and path request stamps, in seconds.

# lr_stamp_timeout = 15
# pr_stamp_timeout = 15


[logging]
# Valid log levels are 0 through 8:
#   0: Log only critical information
#   1: Log errors and lower log levels
#   2: Log warnings and lower log levels
#   3: Log notices and lower log levels
#   4: Log info and lower (this is the default)
#   5: Verbose logging
#   6: Debug logging
#   7: Path logging
#   8: Extreme logging

loglevel = 4

# You can disable timestamp inclusion in logs. Useful if
# you want to use an external logging tool that provides
# its own timestamps or custom formatting.

# logtimestamps = no


# The interfaces section defines the physical and virtual
# interfaces Reticulum will use to communicate on. This
# section will contain examples for a variety of interface
# types. You can modify these or use them as a basis for
# your own config, or simply remove the unused ones.

[interfaces]

  # This interface enables communication with other
  # link-local Reticulum nodes over UDP. It does not
  # need any functional IP infrastructure like routers
  # or DHCP servers, but will require that at least link-
  # local IPv6 is enabled in your operating system, which
  # should be enabled by default in almost any OS. See
  # the Reticulum Manual for more configuration options.

  [[Default Interface]]
    type = AutoInterface
    enabled = yes


  # The following example enables communication with other
  # local Reticulum peers using UDP broadcasts.
  
  [[UDP Interface]]
    type = UDPInterface
    enabled = no
    listen_ip = 0.0.0.0
    listen_port = 4242
    forward_ip = 255.255.255.255
    forward_port = 4242

    # The above configuration will allow communication
    # within the local broadcast domains of all local
    # IP interfaces.

    # Instead of specifying listen_ip, listen_port,
    # forward_ip and forward_port, you can also bind
    # to a specific network device like below.

    # device = eth0
    # port = 4242

    # Assuming the eth0 device has the address
    # 10.55.0.72/24, the above configuration would
    # be equivalent to the following manual setup.
    # Note that we are both listening and forwarding to
    # the broadcast address of the network segments.

    # listen_ip = 10.55.0.255
    # listen_port = 4242
    # forward_ip = 10.55.0.255
    # forward_port = 4242

    # You can of course also communicate only with
    # a single IP address

    # listen_ip = 10.55.0.15
    # listen_port = 4242
    # forward_ip = 10.55.0.16
    # forward_port = 4242


  # This example demonstrates a TCP server interface.
  # It will listen for incoming connections on the
  # specified IP address and port number.
  
  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = no

    # This configuration will listen on all IP
    # interfaces on port 4242
    
    listen_ip = 0.0.0.0
    listen_port = 4242

    # Alternatively you can bind to a specific IP
    
    # listen_ip = 10.0.0.88
    # listen_port = 4242

    # Or a specific network device
    
    # device = eth0
    # port = 4242


  # To connect to a TCP server interface, you would
  # naturally use the TCP client interface. Here's
  # an example. The target_host can either be an IP
  # address or a hostname

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = no
    target_host = 127.0.0.1
    target_port = 4242


  # This example shows how to make your Reticulum
  # instance available over I2P, and connect to
  # another I2P peer. Please be aware that you
  # must have an I2P router running on your system
  # with the SAMv3 API enabled for this to work.

  [[I2P]]
    type = I2PInterface
    enabled = no
    connectable = yes
    peers = ykzlw5ujbaqc2xkec4cpvgyxj257wcrmmgkuxqmqcur7cq3w3lha.b32.i2p


  # Here's an example of how to add a LoRa interface
  # using the RNode LoRa transceiver.

  [[RNode LoRa Interface]]
    type = RNodeInterface

    # Enable interface if you want use it!
    enabled = no

    # Serial port for the device
    port = /dev/ttyUSB0

    # It is also possible to use BLE devices
    # instead of wired serial ports. The
    # target RNode must be paired with the
    # host device before connecting. BLE
    # devices can be connected by name,
    # BLE MAC address or by any available.
    
    # Connect to specific device by name
    # port = ble://RNode 3B87

    # Or by BLE MAC address
    # port = ble://F4:12:73:29:4E:89

    # Or connect to the first available,
    # paired device
    # port = ble://

    # Set frequency to 867.2 MHz
    frequency = 867200000

    # Set LoRa bandwidth to 125 KHz
    bandwidth = 125000

    # Set TX power to 7 dBm (5 mW)
    txpower = 7

    # Select spreading factor 8. Valid 
    # range is 7 through 12, with 7
    # being the fastest and 12 having
    # the longest range.
    spreadingfactor = 8

    # Select coding rate 5. Valid range
    # is 5 throough 8, with 5 being the
    # fastest, and 8 the longest range.
    codingrate = 5

    # You can configure the RNode to send
    # out identification on the channel with
    # a set interval by configuring the
    # following two parameters. The trans-
    # ceiver will only ID if the set
    # interval has elapsed since it's last
    # actual transmission. The interval is
    # configured in seconds.
    # This option is commented out and not
    # used by default.
    # id_callsign = MYCALL-0
    # id_interval = 600

    # For certain homebrew RNode interfaces
    # with low amounts of RAM, using packet
    # flow control can be useful. By default
    # it is disabled.
    flow_control = False
    
    
  # An example KISS modem interface. Useful for running
  # Reticulum over packet radio hardware.

  [[Packet Radio KISS Interface]]
    type = KISSInterface

    # Enable interface if you want use it!
    enabled = no

    # Serial port for the device
    port = /dev/ttyUSB1

    # Set the serial baud-rate and other
    # configuration parameters.
    speed = 115200    
    databits = 8
    parity = none
    stopbits = 1

    # Set the modem preamble. A 150ms
    # preamble should be a reasonable
    # default, but may need to be
    # increased for radios with slow-
    # opening squelch and long TX/RX
    # turnaround
    preamble = 150

    # Set the modem TX tail. In most
    # cases this should be kept as low
    # as possible to not waste airtime.
    txtail = 10

    # Configure CDMA parameters. These
    # settings are reasonable defaults.
    persistence = 200
    slottime = 20

    # You can configure the interface to send
    # out identification on the channel with
    # a set interval by configuring the
    # following two parameters. The KISS
    # interface will only ID if the set
    # interval has elapsed since it's last
    # actual transmission. The interval is
    # configured in seconds.
    # This option is commented out and not
    # used by default.
    # id_callsign = MYCALL-0
    # id_interval = 600

    # Whether to use KISS flow-control.
    # This is useful for modems that have
    # a small internal packet buffer, but
    # support packet flow control instead.
    flow_control = false


  # If you're using Reticulum on amateur radio spectrum,
  # you might want to use the AX.25 KISS interface. This
  # way, Reticulum will automatically encapsulate it's
  # traffic in AX.25 and also identify your stations
  # transmissions with your callsign and SSID.
  # 
  # Only do this if you really need to! Reticulum doesn't
  # need the AX.25 layer for anything, and it incurs extra
  # overhead on every packet to encapsulate in AX.25.
  #
  # A more efficient way is to use the plain KISS interface
  # with the beaconing functionality described above.

  [[Packet Radio AX.25 KISS Interface]]
    type = AX25KISSInterface

    # Set the station callsign and SSID
    callsign = NO1CLL
    ssid = 0

    # Enable interface if you want use it!
    enabled = no

    # Serial port for the device
    port = /dev/ttyUSB2

    # Set the serial baud-rate and other
    # configuration parameters.
    speed = 115200    
    databits = 8
    parity = none
    stopbits = 1

    # Whether to use KISS flow-control.
    # This is useful for modems with a
    # small internal packet buffer.
    flow_control = false

    # Set the modem preamble. A 150ms
    # preamble should be a reasonable
    # default, but may need to be
    # increased for radios with slow-
    # opening squelch and long TX/RX
    # turnaround
    preamble = 150

    # Set the modem TX tail. In most
    # cases this should be kept as low
    # as possible to not waste airtime.
    txtail = 10

    # Configure CDMA parameters. These
    # settings are reasonable defaults.
    persistence = 200
    slottime = 20


"#;

#[derive(Parser)]
#[command(
    name = "rnsd-rs",
    about = "Reticulum Network Stack Daemon",
    disable_version_flag = true
)]
struct Args {
    #[command(subcommand)]
    command: Option<ifac_migration::Command>,
    /// Alternative config directory.
    #[arg(long, short = 'c', hide_short_help = true)]
    config: Option<String>,

    /// Increase verbosity (repeatable; ignored with --service).
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (repeatable; ignored with --service).
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// Log to `<configdir>/logfile` using the configured log level.
    /// The process remains in the foreground.
    #[arg(short = 's', long)]
    service: bool,

    /// Open the built-in status console after initialisation.
    /// Supports the listed status names, not arbitrary shell or Python commands.
    #[arg(short = 'i', long)]
    interactive: bool,

    /// Print verbose configuration example to stdout and exit.
    #[arg(long)]
    exampleconfig: bool,

    /// Print version and exit.
    #[arg(long)]
    version: bool,
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();

    if args.version {
        println!("rnsd-rs {RS_RETICULUM_VERSION} (Reticulum {RETICULUM_COMPAT_VERSION})");
        return;
    }

    if args.exampleconfig {
        print!("{RNSD_EXAMPLE_CONFIG}");
        return;
    }

    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    if let Some(command) = &args.command {
        if let Err(error) = command.run(&config_dir) {
            eprintln!("rnsd-rs: {error}");
            std::process::exit(1);
        }
        return;
    }

    let level = effective_loglevel(&config_dir, args.verbose, args.quiet, args.service);
    let log_timestamps = rns_tools::config_log_timestamps(&config_dir);

    if args.service {
        if let Err(e) = fs::create_dir_all(&config_dir) {
            eprintln!(
                "rnsd-rs: failed to create config directory {}: {e}",
                config_dir.display()
            );
            std::process::exit(1);
        }
        let log_path = config_dir.join("logfile");
        if let Err(e) = rotate_log_if_needed(&log_path) {
            eprintln!(
                "rnsd-rs: failed to rotate logfile {}: {e}",
                log_path.display()
            );
            std::process::exit(1);
        }
        rns_tools::init_tracing(level, log_timestamps, false, LogFileWriter::new(log_path));
    } else {
        rns_tools::init_tracing(level, log_timestamps, true, std::io::stdout);
    }

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let _signal_rx = rns_runtime::lifecycle::install_signal_handlers(shutdown.clone());

    let is_foreground = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    match rns_runtime::reticulum::init(
        args.config.as_deref(),
        None,
        shutdown.clone(),
        is_foreground,
    )
    .await
    {
        Ok(handle) => {
            if handle.instance_mode == rns_runtime::reticulum::InstanceMode::Client {
                tracing::warn!(
                    "Started rnsd-rs version {RS_RETICULUM_VERSION} (Reticulum {RETICULUM_COMPAT_VERSION}) connected to another shared local instance, this is probably NOT what you want!"
                );
            } else {
                rns_transport::notice!(
                    "Started rnsd-rs version {RS_RETICULUM_VERSION} (Reticulum {RETICULUM_COMPAT_VERSION})"
                );
            }
            tracing::info!("reticulum started in {:?} mode", handle.instance_mode);
            // Python's discovery stamps come from RNS itself (Discovery.py).
            handle
                .enable_on_network_discovery(std::sync::Arc::new(
                    rns_transport::discovery::RnsDiscoveryStamper,
                ))
                .await;
            if args.interactive {
                run_interactive_shell(handle.clone()).await;
                shutdown.trigger();
            }

            shutdown.wait().await;
            handle.shutdown_and_wait().await;
            if let Some(interface) = handle.interface_panic() {
                tracing::error!(
                    "interface {interface} failed and panic_on_interface_error is set, exiting"
                );
                // Python `RNS.panic()` exits with status 255.
                std::process::exit(255);
            }
            tracing::info!("rnsd-rs shutting down");
        }
        Err(e) => {
            tracing::error!("failed to start reticulum: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_interactive_shell(handle: rns_runtime::reticulum::ReticulumHandle) {
    let _ = tokio::task::spawn_blocking(move || {
        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut stdout = io::stdout();
        let _ = writeln!(
            stdout,
            "rnsd-rs {RS_RETICULUM_VERSION} interactive console"
        );
        let _ = writeln!(
            stdout,
            "Reticulum instance mode: {:?}",
            handle.instance_mode
        );
        let _ = writeln!(stdout, "Type exit() or press Ctrl-D to return.");

        let mut line = String::new();
        loop {
            line.clear();
            let _ = write!(stdout, ">>> ");
            let _ = stdout.flush();
            match stdin.read_line(&mut line) {
                Ok(0) => {
                    let _ = writeln!(stdout);
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    match trimmed {
                        "" => {}
                        "exit()" | "quit()" | "exit" | "quit" => break,
                        "__version__" => {
                            let _ = writeln!(stdout, "{RETICULUM_COMPAT_VERSION:?}");
                        }
                        "reticulum.is_shared_instance" => {
                            let _ = writeln!(
                                stdout,
                                "{}",
                                py_bool(
                                    handle.instance_mode
                                        == rns_runtime::reticulum::InstanceMode::Shared
                                )
                            );
                        }
                        "reticulum.is_connected_to_shared_instance" => {
                            let _ = writeln!(
                                stdout,
                                "{}",
                                py_bool(
                                    handle.instance_mode
                                        == rns_runtime::reticulum::InstanceMode::Client
                                )
                            );
                        }
                        "reticulum.is_standalone_instance" => {
                            let _ = writeln!(
                                stdout,
                                "{}",
                                py_bool(
                                    handle.instance_mode
                                        == rns_runtime::reticulum::InstanceMode::Standalone
                                )
                            );
                        }
                        "reticulum.configdir" => {
                            let _ = writeln!(stdout, "{:?}", handle.config_dir.display().to_string());
                        }
                        "reticulum.local_socket_path" => {
                            let _ = writeln!(stdout, "{:?}", handle.config.instance_name);
                        }
                        "reticulum.rpc_type" => {
                            let rpc_type = if handle.config.shared_instance_type
                                == rns_runtime::reticulum::SharedInstanceType::Unix
                            {
                                "AF_UNIX"
                            } else {
                                "AF_INET"
                            };
                            let _ = writeln!(stdout, "{rpc_type:?}");
                        }
                        "mode" | "instance_mode" => {
                            let _ = writeln!(stdout, "{:?}", handle.instance_mode);
                        }
                        "config" | "config_dir" => {
                            let _ = writeln!(stdout, "{}", handle.config_dir.display());
                        }
                        "help" | "help()" => {
                            let _ = writeln!(
                                stdout,
                                "Available names: __version__, reticulum, mode, instance_mode, config, config_dir, exit()"
                            );
                        }
                        other => {
                            if let Some(inner) =
                                other.strip_prefix("print(").and_then(|s| s.strip_suffix(')'))
                            {
                                write_interactive_print(&mut stdout, &handle, inner.trim());
                            } else {
                                let _ = writeln!(
                                    stdout,
                                    "NameError: name '{}' is not defined",
                                    other.replace('\'', "\\'")
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(stdout, "I/O error: {e}");
                    break;
                }
            }
        }
    })
    .await;
}

fn py_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

fn write_interactive_print(
    stdout: &mut io::Stdout,
    handle: &rns_runtime::reticulum::ReticulumHandle,
    expr: &str,
) {
    let value = match expr {
        "__version__" => Some(RETICULUM_COMPAT_VERSION.to_string()),
        "reticulum.is_shared_instance" => Some(
            py_bool(handle.instance_mode == rns_runtime::reticulum::InstanceMode::Shared)
                .to_string(),
        ),
        "reticulum.is_connected_to_shared_instance" => Some(
            py_bool(handle.instance_mode == rns_runtime::reticulum::InstanceMode::Client)
                .to_string(),
        ),
        "reticulum.is_standalone_instance" => Some(
            py_bool(handle.instance_mode == rns_runtime::reticulum::InstanceMode::Standalone)
                .to_string(),
        ),
        _ => parse_string_literal(expr),
    };
    let _ = writeln!(stdout, "{}", value.unwrap_or_else(|| expr.to_string()));
}

fn parse_string_literal(value: &str) -> Option<String> {
    value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .map(str::to_string)
}

/// Python `Reticulum.__apply_config`: the configured level plus the `-v`/`-q`
/// delta. A missing file is read as the default config the runtime writes first.
fn effective_loglevel(
    config_dir: &Path,
    verbose: u8,
    quiet: u8,
    service: bool,
) -> rns_tools::LogLevel {
    let path = config_dir.join("config");
    let config = if path.exists() {
        rns_runtime::config::Config::from_file(&path).ok()
    } else {
        rns_runtime::config::Config::parse(rns_runtime::config::Config::default_config()).ok()
    };
    let configured = config
        .as_ref()
        .and_then(|c| c.section("logging")?.get_int("loglevel"));
    rns_tools::Utility::Rnsd.loglevel(configured, verbose, quiet, service)
}

fn rotate_log_if_needed(path: &Path) -> std::io::Result<()> {
    if path.metadata().map(|m| m.len()).unwrap_or(0) < LOG_ROTATE_BYTES {
        return Ok(());
    }
    let rotated = path.with_file_name("logfile.1");
    let _ = fs::remove_file(&rotated);
    fs::rename(path, rotated)
}

#[derive(Clone)]
struct LogFileWriter {
    /// One persistent file handle + in-memory size counter shared across
    /// `make_writer` calls — tracing calls it per event, so per-event opens
    /// and per-write stats would dominate logging cost.
    shared: std::sync::Arc<std::sync::Mutex<RotatingLogFile>>,
}

impl LogFileWriter {
    fn new(path: PathBuf) -> Self {
        Self {
            shared: std::sync::Arc::new(std::sync::Mutex::new(RotatingLogFile {
                path,
                file: None,
                size: 0,
            })),
        }
    }
}

impl<'a> MakeWriter<'a> for LogFileWriter {
    type Writer = SharedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriter(self.shared.clone())
    }
}

/// Per-event writer handle; locks the shared rotating file for each write
/// and falls back to stderr if the logfile cannot be opened.
struct SharedLogWriter(std::sync::Arc<std::sync::Mutex<RotatingLogFile>>);

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.0.lock().expect("log writer mutex poisoned");
        match inner.write(buf) {
            Ok(n) => Ok(n),
            Err(_) => std::io::stderr().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self.0.lock().expect("log writer mutex poisoned");
        match inner.flush() {
            Ok(()) => Ok(()),
            Err(_) => std::io::stderr().flush(),
        }
    }
}

struct RotatingLogFile {
    path: PathBuf,
    file: Option<File>,
    /// Current logfile size, maintained in memory; stat only happens at open.
    size: u64,
}

impl RotatingLogFile {
    fn file_mut(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.size = file.metadata().map(|m| m.len()).unwrap_or(0);
            self.file = Some(file);
        }
        Ok(self.file.as_mut().expect("log file was just opened"))
    }

    fn rotate_if_needed(&mut self) -> io::Result<()> {
        if self.size <= LOG_ROTATE_BYTES {
            return Ok(());
        }

        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }

        let rotated = self.path.with_file_name("logfile.1");
        let _ = fs::remove_file(&rotated);
        match fs::rename(&self.path, &rotated) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?,
        );
        self.size = 0;
        Ok(())
    }
}

impl Write for RotatingLogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.file_mut()?.write(buf)?;
        self.size += written as u64;
        self.rotate_if_needed()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file_mut()?.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_is_added_to_configured_loglevel_and_clamped() {
        use rns_tools::LogLevel;
        let dir = std::env::temp_dir().join(format!("rnsd-loglevel-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config"), "[logging]\nloglevel = 4\n").unwrap();
        assert_eq!(effective_loglevel(&dir, 5, 0, false), LogLevel::Extreme);
        assert_eq!(effective_loglevel(&dir, 0, 9, false), LogLevel::Critical);
        assert_eq!(effective_loglevel(&dir, 3, 0, true), LogLevel::Info);
        fs::write(dir.join("config"), "[reticulum]\n").unwrap();
        assert_eq!(effective_loglevel(&dir, 4, 0, false), LogLevel::Notice);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ifac_units_cli_requires_explicit_units_and_selection() {
        let args = Args::try_parse_from([
            "rnsd-rs",
            "-c",
            "/tmp/config-dir",
            "config",
            "ifac-units",
            "--source-units",
            "bytes",
            "--interface",
            "Radio",
            "--interface",
            "TCP",
        ])
        .unwrap();
        assert_eq!(args.config.as_deref(), Some("/tmp/config-dir"));
        let Some(ifac_migration::Command::Config {
            command:
                ifac_migration::ConfigCommand::IfacUnits {
                    interfaces,
                    units,
                    apply,
                },
        }) = args.command
        else {
            panic!("expected offline migration command")
        };
        assert_eq!(interfaces, ["Radio", "TCP"]);
        assert!(matches!(units, ifac_migration::Units::Bytes));
        assert!(!apply);
        for missing in [
            vec!["rnsd-rs", "config", "ifac-units", "--interface", "Radio"],
            vec!["rnsd-rs", "config", "ifac-units", "--source-units", "bits"],
            vec![
                "rnsd-rs",
                "config",
                "ifac-units",
                "--source-units",
                "guess",
                "--interface",
                "Radio",
            ],
        ] {
            assert!(Args::try_parse_from(missing).is_err());
        }
        assert!(
            Args::try_parse_from([
                "rnsd-rs",
                "config",
                "ifac-units",
                "--source-units",
                "bits",
                "--interface",
                "Radio",
                "--write",
            ])
            .is_ok()
        );
    }
}
