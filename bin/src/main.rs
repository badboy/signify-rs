use anyhow::anyhow;
use anyhow::Result;
use argh::FromArgs;
use crypto::bcrypt_pbkdf::bcrypt_pbkdf;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha512};
use signify_lib::*;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::process;

// https://docs.rs/clap/2.33.3/clap/

#[derive(FromArgs, Debug)]
/// signify-rs -- create cryptographic signatures for files and verify them
struct Args {
    /// generate a new key pair. Keynames should follow the convention of keyname.pub
    /// and keyname.sec for the public and secret keys, respectively.
    #[argh(switch, short = 'G')]
    generate: bool,

    /// sign the specified message file and create a signature.
    #[argh(switch, short = 'S')]
    sign: bool,

    /// verify the message and signature match.
    #[argh(switch, short = 'V')]
    verify: bool,

    /// the signature file to create or verify. The default is message.sig.
    #[argh(option, short = 'x')]
    signature_file: Option<String>,

    /// specify the comment to be added during key generation.
    #[argh(option, short = 'c')]
    comment: Option<String>,

    /// when signing, embed the message after the signature. When verifying, extract the message from the signature.
    /// (This requires that the signature was created using -e and creates a new message file as output.)
    #[argh(switch, short = 'e')]
    embed: bool,

    /// public key produced by -G, and used by -V to check a signature.
    #[argh(option, short = 'p')]
    public_key: Option<String>,

    /// secret (private) key produced by -G, and used by -S to sign a message.
    #[argh(option, short = 's')]
    secret_key: Option<String>,

    /// when signing, the file containing the message to sign. When verifying, the file containing the message to verify.
    /// when verifying with -e, the file to create.
    #[argh(option, short = 'm')]
    message: Option<String>,

    // when generating a key pair, do not ask for a passphrase. Otherwise, signify will prompt the user for a passphrase to protect the secret key.
    /// when signing with -z, store a zero time stamp in the gzip(1) header.
    #[argh(switch, short = 'n')]
    no_passphrase: bool,
}

fn read_password(confirm: bool) -> Result<String> {
    let mut stdout = std::io::stdout();
    stdout.write_all(b"passphrase: ")?;
    stdout.flush()?;

    let passphrase = rpassword::read_password()?;

    if confirm {
        stdout.write_all(b"confirm passphrase: ")?;
        stdout.flush()?;
        let confirm_passphrase = rpassword::read_password()?;
        if passphrase != confirm_passphrase {
            return Err(anyhow!("passwords don't match"));
        }
    }

    Ok(passphrase)
}

fn human(res: Result<()>) {
    match res {
        Err(_e) => {
            process::exit(1);
        }
        Ok(()) => {}
    }
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
    let serialized_pkey = read_base64(&pubkey_path, &mut pubkey)?;
    let pkey = PublicKey::from_buf(&serialized_pkey)?;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path),
    };

    let signature_file = File::open(&signature_path)?;
    let mut sig_data = BufReader::new(signature_file);

    // TODO: Better error message?
    let serialized_signature = read_base64(&signature_path, &mut sig_data)?;
    let signature = Signature::from_buf(&serialized_signature)?;

    let mut msg = vec![];

    if embed {
        sig_data.read_to_end(&mut msg)?;
    } else {
        let mut msgfile = File::open(&msg_path)?;
        msgfile.read_to_end(&mut msg)?;
    }

    if signature.keynum != pkey.keynum {
        return Err(anyhow!(
            "signature verification failed: checked against wrong key",
        ));
    }

    if signature.verify(&msg, &pkey) {
        println!("Signature Verified");
        Ok(())
    } else {
        Err(anyhow!("signature verification failed"))
    }
}

fn sign(
    seckey_path: String,
    msg_path: String,
    signature_path: Option<String>,
    embed: bool,
) -> Result<()> {
    let seckey_file = File::open(&seckey_path)?;
    let mut seckey = BufReader::new(seckey_file);

    let serialized_skey = read_base64(&seckey_path, &mut seckey)?;
    let mut skey = PrivateKey::from_buf(&serialized_skey)?;

    let rounds = skey.kdfrounds;
    let xorkey = if rounds > 0 {
        let passphrase = read_password(false)?;

        let mut xorkey = vec![0; SECRETBYTES];
        bcrypt_pbkdf(passphrase.as_bytes(), &skey.salt, rounds, &mut xorkey);
        xorkey
    } else {
        vec![0; SECRETBYTES]
    };

    for (prv, xor) in skey.seckey.iter_mut().zip(xorkey.iter()) {
        *prv ^= xor;
    }
    let skey = skey;

    let mut msgfile = File::open(&msg_path)?;
    let mut msg = vec![];
    msgfile.read_to_end(&mut msg)?;

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path),
    };

    let sig = skey.sign(&msg)?;

    let mut out = vec![];
    sig.write(&mut out)?;

    let sig_comment = "signature from signify secret key";

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&signature_path)?;

    let mut file = BufWriter::new(file);
    write_base64(&mut file, sig_comment, &out)?;

    if embed {
        file.write_all(&msg)?;
    }

    Ok(())
}

fn generate(
    pubkey_path: String,
    privkey_path: String,
    comment: Option<String>,
    kdfrounds: u32,
) -> Result<()> {
    let comment = match comment {
        Some(s) => s,
        None => "signify".into(),
    };

    let mut keynum = [0; KEYNUMLEN];
    OsRng.fill_bytes(&mut keynum);

    let keypair: Keypair = Keypair::generate(&mut OsRng);
    let pkey = keypair.public.to_bytes();
    let mut skey = keypair.secret.to_bytes();

    let mut salt = [0; 16];
    OsRng.fill_bytes(&mut salt);
    let xorkey = if kdfrounds > 0 {
        let passphrase = read_password(true)?;
        let mut xorkey = vec![0; SECRETBYTES];
        bcrypt_pbkdf(passphrase.as_bytes(), &salt, kdfrounds, &mut xorkey);
        xorkey
    } else {
        vec![0; SECRETBYTES]
    };

    for (prv, xor) in skey.iter_mut().zip(xorkey.iter()) {
        *prv ^= xor;
    }

    // signify stores the extended key as the private key,
    // that is the 32 byte of the secret key, followed by the 32 byte of the public key,
    // summing up to 64 byte.
    let mut complete_key = [0; 64];
    complete_key[0..32].copy_from_slice(&skey);
    complete_key[32..].copy_from_slice(&pkey);

    // Store private key
    let mut hasher = Sha512::default();
    hasher.update(&complete_key);
    let digest = hasher.finalize();
    let mut checksum = [0; 8];
    checksum.copy_from_slice(&digest.as_ref()[0..8]);

    let private_key = PrivateKey {
        pkgalg: PKGALG,
        kdfalg: KDFALG,
        kdfrounds,
        salt,
        checksum,
        keynum,
        seckey: complete_key,
    };

    let mut out = vec![];
    private_key.write(&mut out)?;

    let priv_comment = format!("{} secret key", comment);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&privkey_path)?;

    let mut file = BufWriter::new(file);
    write_base64(&mut file, &priv_comment, &out)?;

    // Store public key
    let public_key = PublicKey::with_key_and_keynum(pkey, keynum);

    let mut out = vec![];
    public_key.write(&mut out)?;

    let pub_comment = format!("{} public key", comment);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pubkey_path)?;

    let mut file = BufWriter::new(file);
    write_base64(&mut file, &pub_comment, &out)
}

fn main() {
    let args: Args = argh::from_env();

    if args.verify {
        human(verify(
            args.public_key.unwrap(),
            args.message.unwrap(),
            args.signature_file,
            args.embed,
        ));
    } else if args.generate {
        let rounds = if args.no_passphrase { 0 } else { 42 };
        human(generate(
            args.public_key.unwrap(),
            args.secret_key.unwrap(),
            args.comment,
            rounds,
        ));
    } else if args.sign {
        human(sign(
            args.secret_key.unwrap(),
            args.message.unwrap(),
            args.signature_file,
            args.embed,
        ));
    }
}
