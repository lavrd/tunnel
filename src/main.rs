use clap::{command, Parser, Subcommand};

#[cfg(feature = "crypto")]
mod crypto;
#[cfg(target_os = "linux")]
mod ioctl;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(feature = "notifications")]
mod notifications;
#[cfg(target_os = "linux")]
mod tunnel;

/// Command line utility to interact with tunnel software.
#[derive(Parser)]
#[clap(name = "tunnel")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[cfg(target_os = "linux")]
    /// Run tunnel.
    Run {
        /// Set tunnel system network interface name.
        #[arg(long)]
        #[arg(default_value = "tun0")]
        tun_iface_name: String,
        /// Set tunnel system network interface IP address.
        #[arg(long)]
        #[arg(default_value = "10.0.0.1/24")]
        tun_iface_ip: String,
        /// UDP server IP address.
        #[arg(long)]
        #[arg(default_value = "0.0.0.0")]
        udp_server_ip: String,
        /// Set UDP server port number.
        #[arg(long)]
        #[arg(default_value = "6688")]
        upd_server_port: u16,
        #[cfg(feature = "crypto")]
        /// Tunnel private key as base64.
        tunnel_private_key: String,
        #[cfg(feature = "crypto")]
        /// Client public key as base64.
        client_public_key: String,
    },
    #[cfg(feature = "crypto")]
    /// Generate new keys for data encrypting.
    Generate {},
    #[cfg(feature = "notifications")]
    /// Temporary command to test system notifications.
    Notify {},
}

#[cfg(all(
    not(target_os = "linux"),
    not(feature = "notifications"),
    not(feature = "crypto")
))]
fn main() {}

#[cfg(any(target_os = "linux", feature = "notifications", feature = "crypto"))]
fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        #[cfg(target_os = "linux")]
        Commands::Run {
            tun_iface_name,
            tun_iface_ip,
            udp_server_ip,
            upd_server_port,
            #[cfg(feature = "crypto")]
                tunnel_private_key: b64_tunnel_private_key,
            #[cfg(feature = "crypto")]
                client_public_key: b64_client_public_key,
        } => {
            #[cfg(not(feature = "crypto"))]
            tunnel::run_tunnel(tun_iface_name, tun_iface_ip, udp_server_ip, upd_server_port)?;
            #[cfg(feature = "crypto")]
            tunnel::run_tunnel(
                tun_iface_name,
                tun_iface_ip,
                udp_server_ip,
                upd_server_port,
                b64_tunnel_private_key,
                b64_client_public_key,
            )?;
        }
        #[cfg(feature = "crypto")]
        Commands::Generate {} => {
            let (private_key, public_key) = crypto::generate();
            eprintln!("Private key: {}", private_key);
            eprintln!("Public key: {}", public_key);
        }
        #[cfg(feature = "notifications")]
        Commands::Notify {} => notifications::send_notification(),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

#[cfg(target_os = "linux")]
pub(crate) fn new_io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

#[cfg(target_os = "linux")]
pub(crate) fn map_io_err_msg<T: ToString>(e: T, msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}: {}", e.to_string(), msg))
}
