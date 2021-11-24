use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::io::{prelude::*, SeekFrom};
use std::path::{Path, PathBuf};
use std::process;

use libsignify::{
    consts::DEFAULT_KDF_ROUNDS, errors::Error, Codeable, NewKeyOpts, PrivateKey, PublicKey,
    Signature,
};

use clap::Parser;

#[derive(Parser)]
#[clap(
    name = "signify",
    override_usage = r#"signify -h
    signify -G [-n] [-c <comment>] -p <pubkey> -s <seckey>
    signify -S [-e] [-x <sigfile>] -s <seckey> -m <message>
    signify -V [-e] [-x <sigfile>] -p <pubkey> -m <message>"#
)]
struct Args {
    #[clap(short = 'G', about = "Generate a new keypair.")]
    generate: bool,
    #[clap(short = 'S', about = "Sign the specified message file.")]
    sign: bool,
    #[clap(short = 'V', about = "Verify a message.")]
    verify: bool,

    #[clap(
        short = 'p',
        about = "Public key produced by -G, and used by -V to check a signature."
    )]
    pubkey: Option<PathBuf>,

    #[clap(
        short = 's',
        about = "Secret (private) key produced by -G, and used by -S to sign a message."
    )]
    seckey: Option<PathBuf>,

    #[clap(
        short = 'n',
        about = "Do not ask for a passphrase during key generation. Otherwise, signify will prompt the user for a passphrase to protect the secret key."
    )]
    skip_key_encryption: bool,

    #[clap(short = 'm')]
    message_path: Option<String>,

    #[clap(
        short = 'e',
        about = "When signing, embed the message after the signature. When verifying, extract the message from the signature."
    )]
    embed_message: bool,

    #[clap(
        short = 'x',
        about = "The signature file to create or verify. The default is <message>.sig."
    )]
    signature_path: Option<String>,

    #[clap(
        short = 'c',
        about = "Specify the comment to be added during key generation"
    )]
    comment: Option<String>,
}

fn write_base64_file<C: Codeable>(file: &mut File, comment: &str, data: &C) -> Result<(), Error> {
    let contents = data.to_file_encoding(comment)?;
    file.write_all(&contents)?;

    Ok(())
}

fn read_base64_file<C: Codeable, R: Read>(reader: &mut BufReader<R>) -> Result<(C, u64), Error> {
    let mut contents = String::with_capacity(1024);
    // Optimization: Read the two lines that have the comment and well structured data
    // instead of the entire file in case the message was large and embedded.
    reader.read_line(&mut contents)?;
    reader.read_line(&mut contents)?;

    C::from_base64(&contents)
}

fn verify(
    pubkey_path: &Path,
    msg_path: &str,
    signature_path: Option<String>,
    embed: bool,
) -> Result<(), Error> {
    let mut pubkey_file = BufReader::new(File::open(pubkey_path)?);
    let public_key: PublicKey = read_base64_file(&mut pubkey_file)?.0;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path),
    };

    let mut sig_data = BufReader::new(File::open(&signature_path)?);

    let (signature, msg_data_pos): (Signature, u64) = read_base64_file(&mut sig_data)?;

    let mut msg = vec![];

    if embed {
        sig_data.seek(SeekFrom::Start(msg_data_pos))?;
        sig_data.read_to_end(&mut msg)?;
    } else {
        let mut msg_file = File::open(msg_path)?;
        msg_file.read_to_end(&mut msg)?;
    }

    public_key.verify(&msg, &signature).map(|_| {
        println!("Signature Verified");
    })
}

fn sign(
    private_key_path: &Path,
    msg_path: &str,
    signature_path: Option<String>,
    embed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut secret_key = BufReader::new(File::open(private_key_path)?);
    let mut secret_key: PrivateKey = read_base64_file(&mut secret_key)?.0;

    if secret_key.is_encrypted() {
        let passphrase = read_passphrase(false)?;
        secret_key.decrypt_with_password(&passphrase)?;
    }

    let mut msg_file = File::open(&msg_path)?;
    let mut msg = vec![];
    msg_file.read_to_end(&mut msg)?;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path),
    };

    let sig = secret_key.sign(&msg)?;

    let sig_comment = "signature from signify secret key";

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&signature_path)?;

    write_base64_file(&mut file, sig_comment, &sig)?;

    if embed {
        file.write_all(&msg)?;
    }

    Ok(())
}

fn read_passphrase(confirm: bool) -> Result<String, Box<dyn std::error::Error>> {
    let passphrase = rpassword::prompt_password_stdout("passphrase: ")?;

    if confirm {
        let confirm_passphrase = rpassword::prompt_password_stdout("confirm passphrase: ")?;

        if passphrase != confirm_passphrase {
            return Err("passwords don't match".into());
        }
    }

    Ok(passphrase)
}

fn generate(
    pubkey_path: &Path,
    privkey_path: &Path,
    comment: Option<&str>,
    kdfrounds: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let comment = comment.unwrap_or("signify");

    let derivation_info = match kdfrounds {
        Some(kdf_rounds) => {
            let passphrase = read_passphrase(true)?;
            NewKeyOpts::Encrypted {
                passphrase,
                kdf_rounds,
            }
        }
        None => NewKeyOpts::NoEncryption,
    };

    // Store the private key
    let mut rng = rand_core::OsRng {};
    let private_key = PrivateKey::derive(&mut rng, derivation_info)?;

    let priv_comment = format!("{} secret key", comment);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(privkey_path)?;

    write_base64_file(&mut file, &priv_comment, &private_key)?;

    // Store public key
    let public_key = private_key.public();

    let pub_comment = format!("{} public key", comment);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pubkey_path)?;

    write_base64_file(&mut file, &pub_comment, &public_key)?;

    Ok(())
}

fn human<T>(res: Result<T, Box<dyn std::error::Error>>) -> T {
    match res {
        Ok(val) => val,
        Err(e) => {
            println!("error: {}", e);
            process::exit(1);
        }
    }
}

fn unwrap_path<T>(kind: &'static str, path: Option<T>) -> T {
    match path {
        Some(p) => p,
        None => {
            println!("missing path to {}", kind);
            process::exit(1)
        }
    }
}

fn main() {
    let args = Args::parse();

    if args.verify {
        let public_key = unwrap_path("pubkey", args.pubkey);
        let message = unwrap_path("message", args.message_path);

        human(
            verify(
                &public_key,
                &message,
                args.signature_path,
                args.embed_message,
            )
            .map_err(|e| e.into()),
        );

        return;
    }

    if args.generate {
        let public_key = unwrap_path("pubkey", args.pubkey);
        let private_key = unwrap_path("seckey", args.seckey);
        let rounds = if args.skip_key_encryption {
            None
        } else {
            Some(DEFAULT_KDF_ROUNDS)
        };

        human(generate(
            &public_key,
            &private_key,
            args.comment.as_deref(),
            rounds,
        ));
        return;
    }

    if args.sign {
        let private_key = unwrap_path("seckey", args.seckey);
        let msg_path = unwrap_path("message", args.message_path);

        human(sign(
            &private_key,
            &msg_path,
            args.signature_path,
            args.embed_message,
        ));
    }
}
