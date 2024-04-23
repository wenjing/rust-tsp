use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::AsyncReadExt;
use tracing::{info, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{cesr::Part, AsyncStore, Error, PrivateVid, ReceivedTspMessage, VerifiedVid, Vid};

#[derive(Debug, Parser)]
#[command(name = "tsp")]
#[command(about = "Send and receive TSP messages", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(
        short,
        long,
        default_value = "database.json",
        help = "Database file path"
    )]
    database: String,
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, help = "Pretty print CESR messages")]
    pretty_print: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(arg_required_else_help = true)]
    Verify { vid: String },
    #[command(arg_required_else_help = true)]
    Create { username: String },
    #[command(arg_required_else_help = true)]
    Send {
        #[arg(short, long, required = true)]
        sender_vid: String,
        #[arg(short, long, required = true)]
        receiver_vid: String,
        #[arg(short, long)]
        non_confidential_data: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    Receive {
        vid: String,
        #[arg(short, long)]
        one: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct DatabaseContents {
    private_vids: Vec<PrivateVid>,
    verified_vids: Vec<Vid>,
}

async fn write_database(database_file: &str, db: &AsyncStore) -> Result<(), Error> {
    let db_path = Path::new(database_file);

    let (private_vids, verified_vids) = db.export()?;

    let db_contents = DatabaseContents {
        private_vids,
        verified_vids,
    };

    let db_contents_json =
        serde_json::to_string_pretty(&db_contents).expect("Could not serialize database");

    tokio::fs::write(db_path, db_contents_json)
        .await
        .expect("Could not write database");

    trace!("persisted database to {database_file}");

    Ok(())
}

async fn read_database(database_file: &str) -> Result<AsyncStore, Error> {
    let db_path = Path::new(database_file);
    if db_path.exists() {
        let contents = tokio::fs::read_to_string(db_path)
            .await
            .expect("Could not read database file");

        let db_contents: DatabaseContents =
            serde_json::from_str(&contents).expect("Could not deserialize database");

        let db = AsyncStore::new();

        trace!("opened database {database_file}");

        for private_vid in db_contents.private_vids {
            trace!("loaded {} (private)", private_vid.identifier());
            db.add_private_vid(private_vid)?;
        }

        for verified_vid in db_contents.verified_vids {
            trace!("loaded {}", verified_vid.identifier());
            db.add_verified_vid(verified_vid)?;
        }

        Ok(db)
    } else {
        let db = AsyncStore::new();
        write_database(database_file, &db).await?;

        info!("created new database");

        Ok(db)
    }
}

fn color_print_part(part: Option<Part>, color: u8) {
    if let Some(Part { prefix, data }) = part {
        print!(
            "\x1b[1;{color}m{}\x1b[0;{color}m{}\x1b[0m",
            Base64UrlUnpadded::encode_string(&prefix),
            Base64UrlUnpadded::encode_string(&data)
        );
    }
}

fn print_message(message: &[u8]) {
    let Ok(parts) = tsp::cesr::decode_message_into_parts(message) else {
        eprintln!("Invalid encoded message");
        return;
    };

    println!("CESR encoded message:");

    color_print_part(Some(parts.prefix), 31);
    color_print_part(Some(parts.sender), 35);
    color_print_part(parts.receiver, 34);
    color_print_part(parts.nonconfidential_data, 32);
    color_print_part(parts.ciphertext, 33);
    color_print_part(Some(parts.signature), 36);

    println!();
}

async fn run() -> Result<(), Error> {
    let args = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact().without_time())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if args.verbose {
                    "tsp=trace"
                } else {
                    "tsp=info"
                }
                .into()
            }),
        )
        .init();

    let mut vid_database = read_database(&args.database).await?;

    match args.command {
        Commands::Verify { vid } => {
            vid_database.verify_vid(&vid).await?;
            write_database(&args.database, &vid_database).await?;

            info!("{vid} is verified and added to the database");
        }
        Commands::Create { username } => {
            let did = format!("did:web:tsp-test.org:user:{username}");
            let transport =
                url::Url::parse(&format!("https://tsp-test.org/user/{username}")).unwrap();
            let private_vid = PrivateVid::bind(&did, transport);

            reqwest::Client::new()
                .post("https://tsp-test.org/add-vid")
                .json(&private_vid)
                .send()
                .await
                .expect("Could not publish VID on server");

            vid_database.add_private_vid(private_vid.clone())?;
            write_database(&args.database, &vid_database).await?;

            info!("created identity {}", private_vid.identifier());
        }
        Commands::Send {
            sender_vid,
            receiver_vid,
            non_confidential_data,
        } => {
            let non_confidential_data = non_confidential_data.as_deref().map(|s| s.as_bytes());

            let mut message = Vec::new();
            tokio::io::stdin()
                .read_to_end(&mut message)
                .await
                .expect("Could not read message from stdin");

            let cesr_message = vid_database
                .send(&sender_vid, &receiver_vid, non_confidential_data, &message)
                .await?;

            if args.pretty_print {
                print_message(&cesr_message);
            }

            info!(
                "sent message ({} bytes) from {sender_vid} to {receiver_vid}",
                message.len()
            );
        }
        Commands::Receive { vid, one } => {
            let mut messages = vid_database.receive(&vid).await?;

            info!("listening for messages...");

            while let Some(Ok(message)) = messages.recv().await {
                match message {
                    ReceivedTspMessage::GenericMessage {
                        sender,
                        nonconfidential_data: _,
                        message,
                        message_type: _,
                    } => {
                        info!(
                            "received message ({} bytes) from {}",
                            message.len(),
                            sender.identifier(),
                        );
                        println!("{}", String::from_utf8_lossy(&message),);
                    }
                    ReceivedTspMessage::RequestRelationship {
                        sender,
                        thread_id: _,
                    } => {
                        info!("received relationship request from {}", sender.identifier(),);
                    }
                    ReceivedTspMessage::AcceptRelationship { sender } => {
                        info!("received accept relationship from {}", sender.identifier(),);
                    }
                    ReceivedTspMessage::CancelRelationship { sender } => {
                        info!("received cancel relationship from {}", sender.identifier(),);
                    }
                    ReceivedTspMessage::ForwardRequest {
                        sender, next_hop, ..
                    } => {
                        info!(
                            "messaging forwarding request from {} to {}",
                            sender.identifier(),
                            next_hop.identifier()
                        );
                    }
                }

                if one {
                    break;
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
