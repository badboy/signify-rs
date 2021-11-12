use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::BufReader;
use std::process;

use serde::Deserialize;

use docopt::Docopt;

mod errors;
mod structs;

use errors::*;
use structs::*;

const USAGE: &str = "
signify-rs

Usage:
  signify -h
  signify -G [-n] [-c <comment>] -p <pubkey> -s <seckey>
  signify -S [-e] [-x <sigfile>] -s <seckey> -m <message>
  signify -V [-e] [-x <sigfile>] -p <pubkey> -m <message>

Options:
  -h --help     Show this screen.
  -c <comment>  Specify the comment to be added during key generation.
  -e            When signing, embed the message after the signature. When verifying extract the message from
                the signature.
  -m <message>  When signing, the file containing the message to sign.  When verifying, the file containing the
                message to verify.  When verifying with -e, the file to create.
  -n            Do not ask for a passphrase during key generation. Otherwise, signify will prompt the user for a
                passphrase to protect the secret key.
  -p <pubkey>   Public key produced by -G, and used by -V to check a signature.
  -s <seckey>   Secret (private) key produced by -G, and used by -S to sign a message.
  -x <sigfile>  The signature file to create or verify.  The default is <message>.sig.
";

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct Args {
    flag_G: bool,
    flag_S: bool,
    flag_V: bool,

    flag_x: Option<String>,
    flag_c: Option<String>,
    flag_e: bool,

    flag_p: String,
    flag_s: String,
    flag_m: String,
    flag_n: bool,
}

fn write_base64_file(file: &mut File, comment: &str, buf: &[u8]) -> Result<()> {
    file.write_all(COMMENTHDR.as_bytes())?;
    writeln!(file, "{}", comment)?;

    let out = base64::encode(buf);
    writeln!(file, "{}", out)?;

    Ok(())
}

fn read_base64_file<R: Read>(file_display: &str, reader: &mut BufReader<R>) -> Result<Vec<u8>> {
    let mut comment_line = String::new();
    reader.read_line(&mut comment_line)?;

    if !comment_line.starts_with(COMMENTHDR) {
        return Err(err_msg(format!(
            "invalid comment in {}; must start with '{}'",
            file_display, COMMENTHDR
        )));
    }

    if !comment_line.ends_with('\n') {
        return Err(err_msg(format!(
            "missing new line after comment in {}",
            file_display
        )));
    }

    if comment_line.len() > COMMENTHDR.len() + COMMENTMAX_LEN {
        return Err(err_msg("comment too long"));
    }

    let mut base64_line = String::new();
    reader.read_line(&mut base64_line)?;

    if base64_line.is_empty() {
        return Err(err_msg(format!("missing line in {}", file_display)));
    }

    if !base64_line.ends_with('\n') {
        return Err(err_msg(format!(
            "missing new line after comment in {}",
            file_display
        )));
    }

    let data = base64::decode(base64_line.trim_end())?;

    if data[0..2] != PKGALG {
        return Err(err_msg(format!("unsupported file {}", file_display)));
    }

    Ok(data)
}

fn verify(
    pubkey_path: String,
    msg_path: String,
    signature_path: Option<String>,
    embed: bool,
) -> Result<()> {
    // TODO: Better error message?

    let pubkey_file = File::open(&pubkey_path)?;
    let mut pubkey = BufReader::new(pubkey_file);
    let serialized_pkey = read_base64_file(&pubkey_path, &mut pubkey)?;
    let public_key = PublicKey::from_buf(&serialized_pkey)?;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path),
    };

    let signature_file = File::open(&signature_path)?;
    let mut sig_data = BufReader::new(signature_file);

    // TODO: Better error message?
    let serialized_signature = read_base64_file(&signature_path, &mut sig_data)?;
    let signature = Signature::from_buf(&serialized_signature)?;

    let mut msg = vec![];

    if embed {
        sig_data.read_to_end(&mut msg)?;
    } else {
        let mut msg_file = File::open(&msg_path)?;
        msg_file.read_to_end(&mut msg)?;
    }

    if signature.keynum != public_key.keynum {
        return Err(err_msg(
            "signature verification failed: checked against wrong key",
        ));
    }

    if signature.verify(&msg, &public_key) {
        println!("Signature Verified");
        Ok(())
    } else {
        Err(err_msg("signature verification failed"))
    }
}

fn sign(
    seckey_path: String,
    msg_path: String,
    signature_path: Option<String>,
    embed: bool,
) -> Result<()> {
    let seckey_file = File::open(&seckey_path)?;
    let mut secret_key = BufReader::new(seckey_file);

    let serialized_skey = read_base64_file(&seckey_path, &mut secret_key)?;
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

fn read_passphrase(confirm: bool) -> Result<String> {
    let passphrase = rpassword::prompt_password_stdout("passphrase: ")?;

    if confirm {
        let confirm_passphrase = rpassword::prompt_password_stdout("confirm passphrase: ")?;

        if passphrase != confirm_passphrase {
            return Err(err_msg("passwords don't match"));
        }
    }

    Ok(passphrase)
}

fn generate(
    pubkey_path: String,
    privkey_path: String,
    comment: Option<&str>,
    kdfrounds: Option<u32>,
) -> Result<()> {
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
        .open(&privkey_path)?;

    write_base64_file(&mut file, &priv_comment, &out)?;

    // Store public key
    let public_key = private_key.public();

    let mut out = vec![];
    public_key.write(&mut out)?;

    let pub_comment = format!("{} public key", comment);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pubkey_path)?;

    write_base64_file(&mut file, &pub_comment, &out)
}

fn human(res: Result<()>) {
    match res {
        Err(e) => {
            println!("error: {}", e.as_fail());

            process::exit(1);
        }
        Ok(()) => {}
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_V {
        human(verify(args.flag_p, args.flag_m, args.flag_x, args.flag_e));
    } else if args.flag_G {
        let rounds = if args.flag_n { None } else { Some(42) };
        human(generate(
            args.flag_p,
            args.flag_s,
            args.flag_c.as_deref(),
            rounds,
        ));
    } else if args.flag_S {
        human(sign(args.flag_s, args.flag_m, args.flag_x, args.flag_e));
    }
}
