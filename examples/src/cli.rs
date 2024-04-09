use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::AsyncReadExt;
use tracing::{info, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tsp::{Error, PrivateVid, ReceivedTspMessage, VerifiedVid, Vid, VidDatabase};

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

async fn write_database(database_file: &str, db: &VidDatabase) -> Result<(), Error> {
    let db_path = Path::new(database_file);

    let (private_vids, verified_vids) = db.export().await?;

    let db_contents = DatabaseContents {
        private_vids,
        verified_vids,
    };

    let db_contents_json = serde_json::to_string_pretty(&db_contents)?;

    tokio::fs::write(db_path, db_contents_json).await?;

    info!("persisted database to {database_file}");

    Ok(())
}

async fn read_database(database_file: &str) -> Result<VidDatabase, Error> {
    let db_path = Path::new(database_file);
    if db_path.exists() {
        let contents = tokio::fs::read_to_string(db_path).await?;
        let db_contents: DatabaseContents = serde_json::from_str(&contents)?;

        let db = VidDatabase::new();

        info!("opened database {database_file}");

        for private_vid in db_contents.private_vids {
            trace!("loaded {} (private)", private_vid.identifier());
            db.add_private_vid(private_vid).await?;
        }

        for verified_vid in db_contents.verified_vids {
            trace!("loaded {}", verified_vid.identifier());
            db.add_verified_vid(verified_vid).await?;
        }

        Ok(db)
    } else {
        let db = VidDatabase::new();
        write_database(database_file, &db).await?;

        info!("created new database");

        Ok(db)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tsp=trace".into()),
        )
        .init();

    let mut vid_database = read_database(&args.database).await?;

    match args.command {
        Commands::Verify { vid } => {
            vid_database.resolve_vid(&vid).await?;
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
                .await?;

            vid_database.add_private_vid(private_vid.clone()).await?;
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
            tokio::io::stdin().read_to_end(&mut message).await?;

            vid_database
                .send(&sender_vid, &receiver_vid, non_confidential_data, &message)
                .await?;

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
                }

                if one {
                    break;
                }
            }
        }
    }

    Ok(())
}
