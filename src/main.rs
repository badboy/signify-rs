extern crate crypto;
extern crate base64;
extern crate byteorder;
extern crate docopt;
#[macro_use]
extern crate serde_derive;
extern crate rpassword;
extern crate ring;
extern crate untrusted;
extern crate failure;

extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;

use std::process;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::{OpenOptions, File};

use crypto::bcrypt_pbkdf::bcrypt_pbkdf;

use rand::Rng;
use rand::OsRng;
use sha2::{Sha512, Digest};
use ed25519_dalek::Keypair;

use docopt::Docopt;

mod structs;
mod errors;

use structs::*;
use errors::*;

const USAGE: &'static str = "
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
    write!(file, "{}", COMMENTHDR)?;
    write!(file, "{}\n", comment)?;
    let out = base64::encode(buf);
    write!(file, "{}\n", out)?;

    Ok(())
}

fn read_base64_file<R: Read>(file_display: &str, reader: &mut BufReader<R>) -> Result<Vec<u8>> {
    let mut comment_line = String::new();
    let len = reader.read_line(&mut comment_line)?;

    if len == 0 || len < COMMENTHDRLEN || !comment_line.starts_with(COMMENTHDR) {
        return Err(err_msg(format!("invalid comment in {}; must start with '{}'", file_display, COMMENTHDR)));
    }

    if &comment_line[len-1..len] != "\n" {
        return Err(err_msg(format!("missing new line after comment in {}", file_display)));
    }

    if len > COMMENTHDRLEN + COMMENTMAXLEN {
        return Err(err_msg("comment too long"));
    }

    let mut base64_line = String::new();
    let len = reader.read_line(&mut base64_line)?;

    if len == 0 {
        return Err(err_msg(format!("missing line in {}", file_display)));
    }

    if &base64_line[len-1..len] != "\n" {
        return Err(err_msg(format!("missing new line after comment in {}", file_display)));
    }

    let base64_line = &base64_line[0..len-1];

    let data = base64::decode(base64_line)?;

    if &data[0..2] != PKGALG {
        return Err(err_msg(format!("unsupported file {}", file_display)));
    }

    Ok(data)
}

fn verify(pubkey_path: String, msg_path: String, signature_path: Option<String>, embed: bool) -> Result<()> {
    // TODO: Better error message?

    let pubkey_file = File::open(&pubkey_path)?;
    let mut pubkey = BufReader::new(pubkey_file);
    let serialized_pkey = read_base64_file(&pubkey_path, &mut pubkey)?;
    let pkey = PublicKey::from_buf(&serialized_pkey)?;


    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path)
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
        let mut msgfile = File::open(&msg_path)?;
        msgfile.read_to_end(&mut msg)?;
    }

    if signature.keynum != pkey.keynum {
        return Err(err_msg("signature verification failed: checked against wrong key"));
    }

    if signature.verify(&msg, &pkey) {
        println!("Signature Verified");
        Ok(())
    } else {
        Err(err_msg("signature verification failed"))
    }
}

fn sign(seckey_path: String, msg_path: String, signature_path: Option<String>, embed: bool) -> Result<()> {
    let seckey_file = File::open(&seckey_path)?;
    let mut seckey = BufReader::new(seckey_file);

    let serialized_skey = read_base64_file(&seckey_path, &mut seckey)?;
    let mut skey = PrivateKey::from_buf(&serialized_skey)?;

    let rounds = skey.kdfrounds;
    let xorkey = kdf(&skey.salt, rounds, false, SECRETBYTES)?;

    for (prv, xor) in skey.seckey.iter_mut().zip(xorkey.iter()) {
        *prv = *prv ^ xor;
    }
    let skey = skey;

    let mut msgfile = File::open(&msg_path)?;
    let mut msg = vec![];
    msgfile.read_to_end(&mut msg)?;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path)
    };

    let sig = skey.sign(&msg)?;

    let mut out = vec![];
    sig.write(&mut out)?;

    let sig_comment = "signature from signify secret key";

    let mut file = OpenOptions::new().write(true).create_new(true).open(&signature_path)?;
    write_base64_file(&mut file, sig_comment, &out)?;

    if embed {
        file.write(&msg)?;
    }

    Ok(())
}

fn read_password(prompt: &str) -> Result<String> {
    let mut stdout = std::io::stdout();
    stdout.write_all(prompt.as_bytes())?;
    stdout.flush()?;

    Ok(rpassword::read_password()?)
}

fn kdf(salt: &[u8], rounds: u32, confirm: bool, keylen: usize) -> Result<Vec<u8>> {
    let mut result = vec![0; keylen];
    if rounds == 0 {
        return Ok(result);
    }

    let passphrase = read_password("passphrase: ")?;

    if confirm {
        let confirm_passphrase = read_password("confirm passphrase: ")?;

        if passphrase != confirm_passphrase {
            return Err(err_msg("passwords don't match"));
        }
    }

    bcrypt_pbkdf(passphrase.as_bytes(), salt, rounds, &mut result);
    Ok(result)
}

fn generate(pubkey_path: String, privkey_path: String, comment: Option<String>, kdfrounds: u32) -> Result<()> {
    let comment = match comment {
        Some(s) => s,
        None    => "signify".into()
    };

    let mut cspring: OsRng = OsRng::new().unwrap();
    let mut keynum = [0; KEYNUMLEN];
    cspring.fill_bytes(&mut keynum);

    let keypair: Keypair = Keypair::generate::<Sha512>(&mut cspring);
    let pkey = keypair.public.to_bytes();
    let mut skey = keypair.secret.to_bytes();

    let mut salt = [0; 16];
    cspring.fill_bytes(&mut salt);

    let xorkey = kdf(&salt, kdfrounds, true, SECRETBYTES)?;

    for (prv, xor) in skey.iter_mut().zip(xorkey.iter()) {
        *prv = *prv ^ xor;
    }

    // signify stores the extended key as the private key,
    // that is the 32 byte of the secret key, followed by the 32 byte of the public key,
    // summing up to 64 byte.
    let mut complete_key = [0; 64];
    complete_key[0..32].copy_from_slice(&skey);
    complete_key[32..].copy_from_slice(&pkey);

    // Store private key
    let mut hasher = Sha512::default();
    hasher.input(&complete_key);
    let digest = hasher.result();
    let mut checksum = [0; 8];
    checksum.copy_from_slice(&digest.as_ref()[0..8]);

    let private_key = PrivateKey {
        pkgalg: PKGALG,
        kdfalg: KDFALG,
        kdfrounds: kdfrounds,
        salt: salt,
        checksum: checksum,
        keynum: keynum,
        seckey: complete_key,
    };

    let mut out = vec![];
    private_key.write(&mut out)?;

    let priv_comment = format!("{} secret key", comment);
    let mut file = OpenOptions::new().write(true).create_new(true).open(&privkey_path)?;
    write_base64_file(&mut file, &priv_comment, &out)?;

    // Store public key
    let public_key = PublicKey::with_key_and_keynum(pkey, keynum);

    let mut out = vec![];
    public_key.write(&mut out)?;

    let pub_comment = format!("{} public key", comment);
    let mut file = OpenOptions::new().write(true).create_new(true).open(&pubkey_path)?;
    write_base64_file(&mut file, &pub_comment, &out)
}

fn human(res: Result<()>) {
    match res {
        Err(e) => {
            println!("error: {}", e.cause());

            process::exit(1);
        },
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
        let rounds = if args.flag_n { 0 } else { 42 };
        human(generate(args.flag_p, args.flag_s, args.flag_c, rounds));
    } else if args.flag_S {
        human(sign(args.flag_s, args.flag_m, args.flag_x, args.flag_e));
    }
}
