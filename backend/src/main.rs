use std::process::exit;

use anyhow::Result;
use drashta::parser::EventData;
use drashta::render::render_app;

fn handle_args() -> u16 {
    let mut args = std::env::args().skip(1);
    let mut port = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                port = args.next().and_then(|x| x.parse::<u16>().ok());
            }
            "--help" | "-h" => {
                print_help();
                exit(0);
            }
            _ => {}
        }
    }
    if port.is_some() { port.unwrap() } else { 3200 }
}
fn print_help() {
    println!(
        r#"Usage: drashta [OPTIONS]

Options:
  -h, --help        Print this help message
  --port <PORT>     Set the server port (default: 3200)
"#
    );
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let (tx, _) = tokio::sync::broadcast::channel::<EventData>(1024);
    let port = handle_args();
    render_app(tx, port).await;

    Ok(())
}
