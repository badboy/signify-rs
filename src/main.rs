use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;

mod errors;
mod structs;

use errors::{Error, FormatError};
use structs::*;

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
        about = "When signing, embed the message after the signature. When verifying, extract the message fromthe signature."
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

fn write_base64_file(file: &mut File, comment: &str, buf: &[u8]) -> Result<(), Error> {
    file.write_all(COMMENTHDR.as_bytes())?;
    writeln!(file, "{}", comment)?;

    let out = base64::encode(buf);
    writeln!(file, "{}", out)?;

    Ok(())
}

fn read_base64_file<R: Read>(reader: &mut BufReader<R>) -> Result<Vec<u8>, Error> {
    let mut comment_line = String::new();
    reader.read_line(&mut comment_line)?;

    if !comment_line.starts_with(COMMENTHDR) {
        return Err(FormatError::Comment {
            expected: COMMENTHDR,
        }
        .into());
    }

    if !comment_line.ends_with('\n') {
        return Err(FormatError::MissingNewline.into());
    }

    if comment_line.len() > COMMENTHDR.len() + COMMENTMAX_LEN {
        return Err(FormatError::LineLength.into());
    }

    let mut base64_line = String::new();
    reader.read_line(&mut base64_line)?;

    if base64_line.is_empty() {
        return Err(FormatError::LineLength.into());
    }

    if !base64_line.ends_with('\n') {
        return Err(FormatError::MissingNewline.into());
    }

    let data = base64::decode(base64_line.trim_end()).map_err(|_| FormatError::Base64)?;

    match data.get(0..2) {
        Some(alg) if alg == PKGALG => Ok(data),
        Some(_) | None => Err(Error::UnsupportedAlgorithm),
    }
}

fn verify(
    pubkey_path: &Path,
    msg_path: &str,
    signature_path: Option<String>,
    embed: bool,
) -> Result<(), Error> {
    // TODO: Better error message?

    let pubkey_file = File::open(pubkey_path)?;
    let mut pubkey = BufReader::new(pubkey_file);
    let serialized_pkey = read_base64_file(&mut pubkey)?;
    let public_key = PublicKey::from_buf(&serialized_pkey)?;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path),
    };

    let signature_file = File::open(&signature_path)?;
    let mut sig_data = BufReader::new(signature_file);

    // TODO: Better error message?
    let serialized_signature = read_base64_file(&mut sig_data)?;
    let signature = Signature::from_buf(&serialized_signature)?;

    let mut msg = vec![];

    if embed {
        sig_data.read_to_end(&mut msg)?;
    } else {
        let mut msg_file = File::open(msg_path)?;
        msg_file.read_to_end(&mut msg)?;
    }

    if signature.keynum != public_key.keynum {
        return Err(Error::MismatchedKey {
            expected: signature.keynum,
            found: public_key.keynum,
        });
    }

    if signature.verify(&msg, &public_key) {
        println!("Signature Verified");
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

fn sign(
    private_key_path: &Path,
    msg_path: &str,
    signature_path: Option<String>,
    embed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let seckey_file = File::open(private_key_path)?;
    let mut secret_key = BufReader::new(seckey_file);

    let serialized_skey = read_base64_file(&mut secret_key)?;
    let mut secret_key = PrivateKey::from_buf(&serialized_skey)?;

    if secret_key.is_encrypted() {
        let passphrase = read_passphrase(false)?;
        secret_key.kdf_mix(&passphrase)?;
    }

    let mut msg_file = File::open(&msg_path)?;
    let mut msg = vec![];
    msg_file.read_to_end(&mut msg)?;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path),
    };

    let sig = secret_key.sign(&msg)?;

    let mut out = vec![];
    sig.write(&mut out)?;

    let sig_comment = "signature from signify secret key";

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&signature_path)?;

    write_base64_file(&mut file, sig_comment, &out)?;

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
    let private_key = PrivateKey::new(derivation_info)?;

    let mut out = vec![];
    private_key.write(&mut out)?;

    let priv_comment = format!("{} secret key", comment);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(privkey_path)?;

    write_base64_file(&mut file, &priv_comment, &out)?;

    // Store public key
    let public_key = private_key.public();

    let mut out = vec![];
    public_key.write(&mut out)?;

    let pub_comment = format!("{} public key", comment);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pubkey_path)?;

    write_base64_file(&mut file, &pub_comment, &out)?;

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
            Some(42)
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
