use byteorder::{ByteOrder, LittleEndian};
use solana_sdk::instruction::Instruction;
use solana_sdk::instruction::AccountMeta;
use solana_sdk::pubkey::Pubkey;
use core::str::FromStr;

use {
    clap::{crate_description, crate_name, crate_version, App, AppSettings, Arg, SubCommand},
    solana_clap_utils::{
        input_parsers::pubkey_of,
        input_validators::{is_url, is_valid_pubkey, is_valid_signer},
        keypair::DefaultSigner,
    },
    solana_client::rpc_client::RpcClient,
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        message::Message,
        native_token::Sol,
        signature::{Signature, Signer},
        system_instruction,
        transaction::Transaction,
    },
    std::{process::exit, sync::Arc},
};

use clokwerk::{Scheduler, TimeUnits};
use std::thread;
use std::time::Duration;

use std::collections::HashMap;

struct Config {
    commitment_config: CommitmentConfig,
    default_signer: Box<dyn Signer>,
    json_rpc_url: String,
    verbose: bool,
}
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Quote {
    date: String,
    avg_price_per_ounce: String,
    jurisdiction: String
}


async fn process_registration(
    rpc_client: &RpcClient,
    signer: &dyn Signer,
    commitment_config: CommitmentConfig,
) -> Result<Signature, Box<dyn std::error::Error>> {
// ) -> Result<String, Box<dyn std::error::Error>> {
    println!("Starting");

    // let mut scheduler = Scheduler::new();
    // scheduler.every(1.seconds()).run(|| println!("Periodic task"));
    // scheduler.run_pending();
    // thread::sleep(Duration::from_millis(10000));
    let resp = reqwest::get("https://api.cluutch.io/v2/daily?date=2021-05-29")
        .await?
        .json::<Vec<Quote>>()
        .await?;

    // let resp = reqwest::blocking::get("https://api.cluutch.io/v2/daily?date=2021-05-29")?
    //     .json::<HashMap<String, String>>();

    println!("{:#?}", resp);
    let p = &resp[0].avg_price_per_ounce;
    println!("{}", p);

    // let mut res = reqwest::blocking::get("https://api.cluutch.io/v2/daily\?date\=2021-05-29")?;
    // let mut body = String::new();
    // res.read_to_string(&mut body)?;

    // println!("Status: {}", res.status());
    // println!("Headers:\n{:#?}", res.headers());
    // println!("Body:\n{}", body);

    // Ok(String::from(p))
    //
    //
    //
    println!("Starting to sign tx");
    let program_id = Pubkey::from_str("6EgWgFtrCsFyhsQLmpQ7sQPCXp3sY3CXEUhSkLjwpGCh")?;
    let data_id = Pubkey::from_str("2BLPJs9kznq3jLWbws9u65o2dN6r3gnyrRJ43rcnQ1ot")?;
    let price: u32 = p.parse::<f32>().unwrap().round() as u32;

    println!("ORIGINAL PRICE: {}", p);
    println!("FINAL PRICE: {}", price);
    let from = signer.pubkey();
    println!("From ID: {}", from);
    println!("Program ID: {}", program_id);
    let mut instruction_data: [u8; 4] = [0; 4];
    LittleEndian::write_u32(&mut instruction_data[0..], price);
    let mut transaction = Transaction::new_with_payer(
        &[Instruction::new(
            program_id,
            &instruction_data,
            vec![AccountMeta::new(data_id, false)],
        )],
        Some(&from),
    );
    println!("Constructed transaction");

    let (recent_blockhash, _fee_calculator) = rpc_client
        .get_recent_blockhash()
        .map_err(|err| format!("error: unable to get recent blockhash: {}", err))?;
    println!("Got recent blockhash");

    transaction
        .try_sign(&vec![signer], recent_blockhash)
        .map_err(|err| format!("error: failed to sign transaction: {}", err))?;
    println!("Signed transaction");

    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner_and_commitment(&transaction, commitment_config)
        .map_err(|err| format!("error: send transaction: {}", err))?;
    println!("Processed transaction");

    println!("{}", signature);
    Ok(signature)
}

fn create_data_account(
    rpc_client: &RpcClient,
    signer: &dyn Signer,
    commitment_config: CommitmentConfig,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let seed = "api.cluutch.io/v2/daily";
    let program_id = Pubkey::from_str("6EgWgFtrCsFyhsQLmpQ7sQPCXp3sY3CXEUhSkLjwpGCh")?;
    let data_num_bytes = 32;
    let data_lamports = 11235813;

    let signer_pub = signer.pubkey();
    println!("Starting to create data account from {} with owner {}", signer_pub, program_id);

    let data_account_pubkey = Pubkey::create_with_seed(&signer.pubkey(), seed, &program_id).unwrap();
    println!("Data account is {}", data_account_pubkey);
    let instruction = system_instruction::create_account_with_seed(&signer_pub, &data_account_pubkey, &signer_pub, seed, data_lamports, data_num_bytes, &program_id);

    let mut transaction = Transaction::new_with_payer(
        &[instruction],
        Some(&signer_pub),
    );
    println!("Constructed account transaction");

    let (recent_blockhash, _fee_calculator) = rpc_client
        .get_recent_blockhash()
        .map_err(|err| format!("error: unable to get recent blockhash: {}", err))?;
    println!("Got recent blockhash");

    transaction
        .try_sign(&vec![signer], recent_blockhash)
        .map_err(|err| format!("error: failed to sign transaction: {}", err))?;
    println!("Signed account transaction");

    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner_and_commitment(&transaction, commitment_config)
        .map_err(|err| format!("error: send transaction: {}", err))?;
    println!("Processed account transaction");
    
    Ok(signature)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(&config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("keypair")
                .long("keypair")
                .value_name("KEYPAIR")
                .validator(is_valid_signer)
                .takes_value(true)
                .global(true)
                .help("Filepath or URL to a keypair [default: client keypair]"),
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .takes_value(false)
                .global(true)
                .help("Show additional information"),
        )
        .arg(
            Arg::with_name("json_rpc_url")
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .global(true)
                .validator(is_url)
                .help("JSON RPC URL for the cluster [default: value from configuration file]"),
        )
        .subcommand(SubCommand::with_name("register").about("Get balance").arg(
            Arg::with_name("endpoint")
            .long("endpoint")
            .short("e")
            .value_name("ENDPOINT")
            .takes_value(true)
            .global(true)
            .validator(is_url)
            .help("Full URL of the API's endpoint"),
        ))
        .subcommand(SubCommand::with_name("create-data-account").about("Create data account"))
        .get_matches();

    let (sub_command, sub_matches) = app_matches.subcommand();
    let matches = sub_matches.unwrap();
    let mut wallet_manager: Option<Arc<RemoteWalletManager>> = None;

    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };

        let default_signer = DefaultSigner {
            path: matches
                .value_of(&"keypair")
                .map(|s| s.to_string())
                .unwrap_or_else(|| cli_config.keypair_path.clone()),
            arg_name: "keypair".to_string(),
        };

        Config {
            json_rpc_url: matches
                .value_of("json_rpc_url")
                .unwrap_or(&cli_config.json_rpc_url)
                .to_string(),
            default_signer: default_signer
                .signer_from_path(&matches, &mut wallet_manager)
                .unwrap_or_else(|err| {
                    eprintln!("error: {}", err);
                    exit(1);
                }),
            verbose: matches.is_present("verbose"),
            commitment_config: CommitmentConfig::confirmed(),
        }
    };
    solana_logger::setup_with_default("solana=info");

    if config.verbose {
        println!("JSON RPC URL: {}", config.json_rpc_url);
    }
    let rpc_client = RpcClient::new(config.json_rpc_url.clone());

    match (sub_command, sub_matches) {
        ("register", Some(_arg_matches)) => {
            let signature = process_registration(
                &rpc_client,
                config.default_signer.as_ref(),
                config.commitment_config,
            ).await
            .unwrap_or_else(|err| {
                eprintln!("error: send transaction: {}", err);
                exit(1);
            });
            println!("Signature: {}", signature);
        },
        ("create-data-account", Some(_arg_matches)) => {
            let mut signature = create_data_account(
                &rpc_client,
                config.default_signer.as_ref(),
                config.commitment_config,
            )
            .unwrap_or_else(|err| {
                eprintln!("error: send transaction: {}", err);
                exit(1);
            });
            println!("Signature: {}", signature);
        }
        _ => unreachable!(),
    };

    Ok(())
}

#[cfg(test)]
mod test {
    use {super::*, solana_validator::test_validator::*};

    // #[test]
    // fn test_ping() {
    //     let (test_validator, payer) = TestValidatorGenesis::default().start();
    //     let (rpc_client, _recent_blockhash, _fee_calculator) = test_validator.rpc_client();

    //     assert!(matches!(
    //         process_ping(
    //             &rpc_client,
    //             &payer,
    //             CommitmentConfig::single_gossip()
    //         ),
    //         Ok(_)
    //     ));
    // }
}
