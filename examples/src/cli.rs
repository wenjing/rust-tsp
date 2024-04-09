use std::path::Path;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tsp::{Error, PrivateVid, Vid, VidDatabase, VerifiedVid};

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

    print!("> persisted database to {database_file}");

    Ok(())
}

async fn read_database(database_file: &str) -> Result<VidDatabase, Error> {
    let db_path = Path::new(database_file);
    if db_path.exists() {
        let contents = tokio::fs::read_to_string(db_path).await?;
        let db_contents: DatabaseContents = serde_json::from_str(&contents)?;

        let db = VidDatabase::new();

        println!("> opened database {database_file}");

        for private_vid in db_contents.private_vids {
            println!("* loaded {} (private)", private_vid.identifier());
            db.add_private_vid(private_vid).await?;
        }

        for verified_vid in db_contents.verified_vids {
            println!("* loaded {}", verified_vid.identifier());
            db.add_verified_vid(verified_vid).await?;
        }

        Ok(db)
    } else {
        let db = VidDatabase::new();
        write_database(database_file, &db).await?;

        print!("> created new database");

        Ok(db)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Cli::parse();

    let mut vid_database = read_database(&args.database).await?;

    match args.command {
        Commands::Verify { vid } => {
            vid_database.resolve_vid(&vid).await?;
            println!("> {vid} is verified and added to the database");
        }
        Commands::Create { username } => {
            let did = format!("did:web:tsp-test.org:user:{username}");
            let transport = url::Url::parse(&format!("https://tsp-test.org/user/{username}")).unwrap();
            let private_vid = PrivateVid::bind(&did, transport);

            reqwest::Client::new()
                .post("https://tsp-test.org/add-vid")
                .json(&private_vid)
                .send()
                .await?;

            vid_database.add_private_vid(private_vid.clone()).await?;

            println!("> created identity {}", private_vid.identifier());
        }
        _ => println!("Nope"),
    }

    write_database(&args.database, &vid_database).await?;

    Ok(())
}
