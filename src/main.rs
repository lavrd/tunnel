use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine};
use clap::{command, Parser, Subcommand};
use ed25519_dalek::SigningKey;
#[cfg(target_os = "linux")]
use ipnet::Ipv4Net;
use rand::rngs::OsRng;

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
        tun_iface_ip: Ipv4Net,
        /// UDP server IP address.
        #[arg(long)]
        #[arg(default_value = "0.0.0.0")]
        udp_server_ip: String,
        /// Set UDP server port number.
        #[arg(long)]
        #[arg(default_value = "6688")]
        upd_server_port: u16,
        /// Tunnel private key as base64.
        tunnel_private_key: String,
        /// Client public key as base64.
        client_public_key: String,
    },
    /// Generate new keys for data encrypting.
    Generate {},
    #[cfg(feature = "notifications")]
    /// Temporary command to test system notifications.
    Notify {},
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        #[cfg(target_os = "linux")]
        Commands::Run {
            tun_iface_name,
            tun_iface_ip,
            udp_server_ip,
            upd_server_port,
            tunnel_private_key: b64_tunnel_private_key,
            client_public_key: b64_client_public_key,
        } => tunnel::run_tunnel(
            tun_iface_name,
            tun_iface_ip,
            udp_server_ip,
            upd_server_port,
            b64_tunnel_private_key,
            b64_client_public_key,
        )?,
        Commands::Generate {} => {
            let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
            let mut private_key = String::new();
            B64_STANDARD.encode_string(signing_key.as_bytes(), &mut private_key);
            let mut public_key = String::new();
            B64_STANDARD.encode_string(signing_key.verifying_key().as_bytes(), &mut public_key);
            eprintln!("Private key: {}", private_key);
            eprintln!("Public key: {}", public_key);
        }
        #[cfg(feature = "notifications")]
        Commands::Notify {} => notifications::send_notification(),
    }
    Ok(())
}
