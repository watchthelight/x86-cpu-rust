use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(name = "x86-sim", version, about = "x86 logical simulator", long_about=None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Run {
        #[arg(long)]
        bin: Option<String>,
        #[arg(long)]
        elf: Option<String>,
        #[arg(long)]
        entry: Option<String>,
        #[arg(long)]
        real: bool,
        #[arg(long)]
        smp: Option<usize>,
        #[arg(long)]
        deterministic: Option<bool>,
    },
    Dbg {
        #[arg(long)]
        connect: Option<String>,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { bin, elf, entry, real, smp, deterministic } => {
            println!("run: bin={bin:?} elf={elf:?} entry={entry:?} real={real} smp={smp:?} det={deterministic:?}");
            // TODO: wire loaders + cpu-core execution loop
        }
        Cmd::Dbg { connect } => {
            println!("dbg: connect={connect:?}");
        }
    }
    Ok(())
}

