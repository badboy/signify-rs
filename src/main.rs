extern crate crypto;
extern crate base64;
extern crate byteorder;
extern crate docopt;
extern crate rustc_serialize;
extern crate rpassword;
extern crate ring;
extern crate untrusted;
#[macro_use]
extern crate error_chain;

use std::process;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::{OpenOptions, File};

use ring::rand::{SystemRandom, SecureRandom};
use ring::signature::Ed25519KeyPair;
use ring::digest;
use crypto::bcrypt_pbkdf::bcrypt_pbkdf;

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
#[derive(Debug, RustcDecodable)]
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
    try!(write!(file, "{}", COMMENTHDR));
    try!(write!(file, "{}\n", comment));
    let out = base64::encode(buf);
    try!(write!(file, "{}\n", out));

    Ok(())
}

fn read_base64_file<R: Read>(file_display: &str, reader: &mut BufReader<R>) -> Result<Vec<u8>> {
    let mut comment_line = String::new();
    let len = try!(reader.read_line(&mut comment_line));

    if len == 0 || len < COMMENTHDRLEN || !comment_line.starts_with(COMMENTHDR) {
        return Err(format!("invalid comment in {}; must start with '{}'", file_display, COMMENTHDR).into());
    }

    if &comment_line[len-1..len] != "\n" {
        return Err(format!("missing new line after comment in {}", file_display).into());
    }

    if len > COMMENTHDRLEN + COMMENTMAXLEN {
        return Err("comment too long".into());
    }

    let mut base64_line = String::new();
    let len = try!(reader.read_line(&mut base64_line));

    if len == 0 {
        return Err(format!("missing line in {}", file_display).into());
    }

    if &base64_line[len-1..len] != "\n" {
        return Err(format!("missing new line after comment in {}", file_display).into());
    }

    let base64_line = &base64_line[0..len-1];

    let data = try!(base64::decode(base64_line)
                    .chain_err(|| format!("invalid base64 encoding in {}", file_display)));

    if &data[0..2] != PKGALG {
        return Err(format!("unsupported file {}", file_display).into());
    }

    Ok(data)
}

fn verify(pubkey_path: String, msg_path: String, signature_path: Option<String>, embed: bool) -> Result<()> {
    // TODO: Better error message?

    let pubkey_file = try!(File::open(&pubkey_path));
    let mut pubkey = BufReader::new(pubkey_file);
    let serialized_pkey = try!(read_base64_file(&pubkey_path, &mut pubkey));
    let pkey = try!(PublicKey::from_buf(&serialized_pkey));


    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path)
    };

    let signature_file = try!(File::open(&signature_path));
    let mut sig_data = BufReader::new(signature_file);

    // TODO: Better error message?
    let serialized_signature = try!(read_base64_file(&signature_path, &mut sig_data));
    let signature = try!(Signature::from_buf(&serialized_signature));


    let mut msg = vec![];

    if embed {
        try!(sig_data.read_to_end(&mut msg).chain_err(|| read_error(&msg_path)));
    } else {
        let mut msgfile = try!(File::open(&msg_path).chain_err(|| read_error(&msg_path)));
        try!(msgfile.read_to_end(&mut msg).chain_err(|| read_error(&msg_path)));
    }

    if signature.keynum != pkey.keynum {
        return Err("signature verification failed: checked against wrong key".into());
    }

    if signature.verify(&msg, &pkey) {
        println!("Signature Verified");
        Ok(())
    } else {
        Err("signature verification failed".into())
    }
}

fn sign(seckey_path: String, msg_path: String, signature_path: Option<String>, embed: bool) -> Result<()> {
    let seckey_file = try!(File::open(&seckey_path));
    let mut seckey = BufReader::new(seckey_file);

    let serialized_skey = try!(read_base64_file(&seckey_path, &mut seckey));
    let mut skey = try!(PrivateKey::from_buf(&serialized_skey));

    let rounds = skey.kdfrounds;
    let xorkey = try!(kdf(&skey.salt, rounds, false, SECRETBYTES));

    for (prv, xor) in skey.seckey.iter_mut().zip(xorkey.iter()) {
        *prv = *prv ^ xor;
    }
    let skey = skey;

    let mut msgfile = try!(File::open(&msg_path)
                           .chain_err(|| read_error(&msg_path)).into());
    let mut msg = vec![];
    try!(msgfile.read_to_end(&mut msg).chain_err(|| read_error(&msg_path)));

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path)
    };

    let sig = try!(skey.sign(&msg).chain_err(|| "Failed to sign message"));

    let mut out = vec![];
    try!(sig.write(&mut out).chain_err(|| "Can't write to internal buffer"));

    let sig_comment = "signature from signify secret key";

    let mut file = try!(OpenOptions::new().write(true).create_new(true).open(&signature_path));
    try!(write_base64_file(&mut file, sig_comment, &out)
        .chain_err(|| "Failed to write signature file"));

    if embed {
        try!(file.write(&msg));
    }

    Ok(())
}

fn read_password(prompt: &str) -> Result<String> {
    let mut stdout = std::io::stdout();
    try!(stdout.write_all(prompt.as_bytes()).chain_err(|| "Write to stdout failed"));
    try!(stdout.flush().chain_err(|| "Flushing stdout failed"));

    rpassword::read_password()
        .chain_err(|| "unable to read passphrase")
}

fn kdf(salt: &[u8], rounds: u32, confirm: bool, keylen: usize) -> Result<Vec<u8>> {
    let mut result = vec![0; keylen];
    if rounds == 0 {
        return Ok(result);
    }

    let passphrase = try!(read_password("passphrase: "));

    if confirm {
        let confirm_passphrase = try!(read_password("confirm passphrase: "));

        if passphrase != confirm_passphrase {
            return Err("passwords don't match".into());
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

    let mut keynum = [0; KEYNUMLEN];
    try!(SystemRandom.fill(&mut keynum).chain_err(|| "Can't fill keynum randomly"));

    let pkcs8 = try!(Ed25519KeyPair::generate_pkcs8(&SystemRandom));
    let mut skey = [0; 32];
    let mut pkey = [0; 32];
    let mut complete_key = [0; 64];

    // signify stores the extended key as the private key,
    // that is the 32 byte of the secret key, followed by the 32 byte of the public key,
    // summing up to 64 byte.
    //
    //  *ring* only gives access to the pkcs8 encoding.
    //  We hackily extract the data from there.
    //
    //  The pkcs8 format is:
    //  "prefix||private_key||middle||public_key"
    //
    //  The private key begins at 0x10 = 16,
    //  the public key is at the end
    const PKCS8_SEED_INDEX : usize = 0x10;

    skey.copy_from_slice(&pkcs8[PKCS8_SEED_INDEX..(PKCS8_SEED_INDEX + 32)]);
    pkey.copy_from_slice(&pkcs8[(pkcs8.len()-32)..]);
    complete_key[0..32].copy_from_slice(&skey);
    complete_key[32..].copy_from_slice(&pkey);
    Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(&skey),
        untrusted::Input::from(&pkey)
    )?;


    let mut salt = [0; 16];
    try!(SystemRandom.fill(&mut salt).chain_err(|| "Can't fill salt randomly"));

    let xorkey = try!(kdf(&salt, kdfrounds, true, SECRETBYTES));

    for (prv, xor) in skey.iter_mut().zip(xorkey.iter()) {
        *prv = *prv ^ xor;
    }

    // Store private key
    let digest = digest::digest(&digest::SHA512, &complete_key);
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
    try!(private_key.write(&mut out).chain_err(|| "Can't write to internal buffer"));

    let priv_comment = format!("{} secret key", comment);
    let mut file = try!(OpenOptions::new().write(true).create_new(true).open(&privkey_path));
    try!(write_base64_file(&mut file, &priv_comment, &out)
        .chain_err(|| write_error(&privkey_path)));

    // Store public key
    let public_key = PublicKey::with_key_and_keynum(pkey, keynum);

    let mut out = vec![];
    try!(public_key.write(&mut out).chain_err(|| "Can't write to internal buffer"));

    let pub_comment = format!("{} public key", comment);
    let mut file = try!(OpenOptions::new().write(true).create_new(true).open(&pubkey_path));
    write_base64_file(&mut file, &pub_comment, &out)
        .chain_err(|| write_error(&pubkey_path))
}

fn human(res: Result<()>) {
    match res {
        Err(e) => {
            let mut it = e.iter();
            let e = it.next().unwrap(); // We have an error, so we can definitely unwrap it.
            let next_err = it.next();
            if let Some(next_err) = next_err {
                println!("{}: {}", e, next_err);
            } else {
                println!("{}", e);
            }

            process::exit(1);
        },
        Ok(()) => {}
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
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
