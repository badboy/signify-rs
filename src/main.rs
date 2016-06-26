extern crate crypto;
extern crate base64;
extern crate byteorder;
extern crate rand;
extern crate docopt;
extern crate rustc_serialize;
extern crate rpassword;

use std::process;
use std::mem;
use std::io::prelude::*;
use std::io::{self, BufReader, Cursor};
use std::io::Result as IoResult;
use std::fs::File;
use std::convert::AsRef;
use std::path::Path;

use rand::Rng;
use rand::os::OsRng;

use crypto::ed25519;
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use crypto::bcrypt_pbkdf::bcrypt_pbkdf;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use docopt::Docopt;


const KEYNUMLEN : usize = 8;
const PUBLICBYTES : usize = 32;
const SECRETBYTES : usize = 64;
const SIGBYTES : usize = 64;

const PKGALG : [u8; 2] = *b"Ed";
const KDFALG : [u8; 2] = *b"BK";

const COMMENTHDR : &'static str = "untrusted comment: ";
const COMMENTHDRLEN : usize = 19;
const COMMENTMAXLEN : usize = 1024;

const USAGE: &'static str = "
signify-rs

Usage:
  signify -h
  signify -G [-n] [-c <comment>] -p <pubkey> -s <seckey>
  signify -S [-x <sigfile>] -s <seckey> -m <message>
  signify -V [-x <sigfile>] -p <pubkey> -m <message>

Options:
  -h --help              Show this screen.
  -c <comment>  Specify the comment to be added during key generation.
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

    flag_p: String,
    flag_s: String,
    flag_m: String,
    flag_n: bool,
}

enum FileContent {
    PublicKey(PublicKey),
    PrivateKey(PrivateKey),
    Signature(Signature),
}


struct PublicKey {
    pkgalg: [u8; 2],
    keynum: [u8; KEYNUMLEN],
    publkey: [u8; PUBLICBYTES],
}

struct PrivateKey {
   pkgalg: [u8; 2],
   kdfalg: [u8; 2],
   kdfrounds: u32,
   salt: [u8; 16],
   checksum: [u8; 8],
   keynum: [u8; KEYNUMLEN],
   seckey: [u8; SECRETBYTES],
}

struct Signature {
    pkgalg: [u8; 2],
    keynum: [u8; KEYNUMLEN],
    sig: [u8; SIGBYTES],
}

impl PublicKey {
    fn with_key_and_keynum(key: [u8; PUBLICBYTES], keynum: [u8; KEYNUMLEN]) -> PublicKey {
        PublicKey {
            pkgalg: PKGALG,
            keynum: keynum,
            publkey: key,
        }
    }

    fn write<W: Write>(&self, mut w: W) -> Result<(), io::Error> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.keynum));
        try!(w.write(&self.publkey));

        Ok(())
    }

    fn from_buf(buf: &[u8]) -> Result<PublicKey, io::Error> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut publkey = [0; PUBLICBYTES];

        try!(buf.read(&mut pkgalg));
        try!(buf.read(&mut keynum));
        try!(buf.read(&mut publkey));

        Ok(PublicKey {
            pkgalg: pkgalg,
            keynum: keynum,
            publkey: publkey,
        })
    }
}

impl PrivateKey {
    fn write<W: Write>(&self, mut w: W) -> Result<(), io::Error> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.kdfalg));
        try!(w.write_u32::<BigEndian>(self.kdfrounds));
        try!(w.write(&self.salt));
        try!(w.write(&self.checksum));
        try!(w.write(&self.keynum));
        try!(w.write(&self.seckey));

        Ok(())
    }

    fn from_buf(buf: &[u8]) -> Result<PrivateKey, io::Error> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut kdfalg = [0; 2];
        let kdfrounds;
        let mut salt = [0; 16];
        let mut checksum = [0; 8];
        let mut keynum = [0; KEYNUMLEN];
        let mut seckey = [0; SECRETBYTES];

        try!(buf.read(&mut pkgalg));
        try!(buf.read(&mut kdfalg));
        kdfrounds = try!(buf.read_u32::<BigEndian>());
        try!(buf.read(&mut salt));
        try!(buf.read(&mut checksum));
        try!(buf.read(&mut keynum));
        try!(buf.read(&mut seckey));

        Ok(PrivateKey {
            pkgalg: pkgalg,
            kdfalg: kdfalg,
            kdfrounds: kdfrounds,
            salt: salt,
            checksum: checksum,
            keynum: keynum,
            seckey: seckey,
        })
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let signature = ed25519::signature(msg, &self.seckey);
        Signature {
            pkgalg: PKGALG,
            keynum: self.keynum,
            sig: signature
        }
    }
}

impl Signature {
    fn write<W: Write>(&self, mut w: W) -> Result<(), io::Error> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.keynum));
        try!(w.write(&self.sig));

        Ok(())
    }

    fn from_buf(buf: &[u8]) -> Result<Signature, io::Error> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut sig = [0; SIGBYTES];

        try!(buf.read(&mut pkgalg));
        try!(buf.read(&mut keynum));
        try!(buf.read(&mut sig));

        Ok(Signature {
            pkgalg: pkgalg,
            keynum: keynum,
            sig: sig,
        })
    }

    fn verify(&self, msg: &[u8], pkey: &PublicKey) -> bool {
        ed25519::verify(msg, &pkey.publkey, &self.sig)
    }
}

fn write_base64_file<P: AsRef<Path>>(file: P, comment: &str, buf: &[u8]) -> Result<(), io::Error> {
    let mut f = File::create(file).unwrap();

    try!(write!(f, "{}", COMMENTHDR));
    try!(write!(f, "{}\n", comment));
    let out = base64::encode(buf);
    try!(write!(f, "{}\n", out));

    Ok(())
}

fn read_base64_file<P: AsRef<Path>>(file: P) -> Result<FileContent, io::Error> {
    let file_display = format!("{}", file.as_ref().display());
    let f = try!(File::open(file));
    let mut reader = BufReader::new(f);

    let mut comment_line = String::new();
    let len = try!(reader.read_line(&mut comment_line));

    if len == 0 || len < COMMENTHDRLEN || !comment_line.starts_with(COMMENTHDR) {
        println!("invalid comment in {}; must start with '{}'", file_display, COMMENTHDR);
        process::exit(1);
    }

    if &comment_line[len-1..len] != "\n" {
        println!("missing new line after comment in '{}'", file_display);
        process::exit(1);
    }

    if len > COMMENTHDRLEN + COMMENTMAXLEN {
        println!("comment too long");
        process::exit(1);
    }

    let mut base64_line = String::new();
    let len = try!(reader.read_line(&mut base64_line));

    if len == 0 {
        println!("missing line in {}", file_display);
        process::exit(1);
    }

    if &base64_line[len-1..len] != "\n" {
        println!("missing new line after comment in '{}'", file_display);
        process::exit(1);
    }

    let base64_line = &base64_line[0..len-1];

    let data = match base64::decode(base64_line) {
        Ok(data) => data,
        Err(e) => {
            println!("invalid base64 encoding in {}: {:?}", file_display, e);
            process::exit(1);
        }
    };

    if &data[0..2] != PKGALG {
        println!("unsupported file {}", file_display);
        process::exit(1);
    }

    match data.len() {
        x if x == mem::size_of::<PublicKey>() => {
            return PublicKey::from_buf(&data)
                .map(FileContent::PublicKey);
        },
        x if x == mem::size_of::<PrivateKey>() => {
            return PrivateKey::from_buf(&data)
                .map(FileContent::PrivateKey);
        },
        x if x == mem::size_of::<Signature>() => {
            return Signature::from_buf(&data)
                .map(FileContent::Signature);
        },
        _ => {
            println!("unsupported file {}", file_display);
            process::exit(1);
        },
    };
}

fn verify(pubkey_path: String, msg_path: String, signature_path: Option<String>) {
    let pkey = match read_base64_file(&pubkey_path) {
        Ok(FileContent::PublicKey(pkey)) => pkey,
        _ => {
            println!("an error occured.");
            process::exit(2);
        }
    };

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path)
    };

    let signature = match read_base64_file(&signature_path) {
        Ok(FileContent::Signature(sig)) => sig,
        _ => {
            println!("Can't read signature from '{}'", signature_path);
            process::exit(2);
        }
    };

    let mut msgfile = File::open(&msg_path).expect(&format!("Can't open message file '{}'", msg_path));
    let mut msg = vec![];
    msgfile.read_to_end(&mut msg).expect(&format!("Can't read file '{}'", msg_path));

    if signature.verify(&msg, &pkey) {
        println!("Signature Verified");
    } else {
        println!("signature verification failed");
        process::exit(1);
    }
}

fn sign(seckey_path: String, msg_path: String, signature_path: Option<String>) {
    let mut skey = match read_base64_file(&seckey_path) {
        Ok(FileContent::PrivateKey(skey)) => skey,
        _ => {
            println!("an error occured.");
            process::exit(2);
        }
    };

    let rounds = skey.kdfrounds;
    let xorkey = kdf(&skey.salt, rounds, false, SECRETBYTES);

    for (prv, xor) in skey.seckey.iter_mut().zip(xorkey.iter()) {
        *prv = *prv ^ xor;
    }
    let skey = skey;

    let mut msgfile = File::open(&msg_path).expect(&format!("Can't open message file '{}'", msg_path));
    let mut msg = vec![];
    msgfile.read_to_end(&mut msg).expect(&format!("Can't read file '{}'", msg_path));

    let signature_path = match signature_path {
        Some(path) => path,
        None => format!("{}.sig", msg_path)
    };

    let sig = skey.sign(&msg);

    let mut out = vec![];
    sig.write(&mut out).expect("Can't write to internal buffer");

    let sig_comment = "signature from signify secret key";
    write_base64_file(&signature_path, sig_comment, &out).unwrap();
}

fn read_password(prompt: &str) -> IoResult<String> {
    let mut stdout = std::io::stdout();
    stdout.write_all(prompt.as_bytes()).expect("Write to stdout failed");
    stdout.flush().expect("Flushing stdout failed");

    rpassword::read_password()
}

fn kdf(salt: &[u8], rounds: u32, confirm: bool, keylen: usize) -> Vec<u8> {
    let mut result = vec![0; keylen];
    if rounds == 0 {
        return result;
    }

    let passphrase = read_password("passphrase: ").expect("unable to read passphrase");

    if confirm {
        let confirm_passphrase = read_password("confirm passphrase: ").expect("unable to read passphrase");

        if passphrase != confirm_passphrase {
            println!("passwords don't match");
            process::exit(1);
        }
    }

    bcrypt_pbkdf(passphrase.as_bytes(), salt, rounds, &mut result);
    result
}

fn generate(pubkey_path: String, privkey_path: String, comment: Option<String>, kdfrounds: u32) {
    let comment = match comment {
        Some(s) => s,
        None    => "signify".into()
    };

    let mut keynum = [0; KEYNUMLEN];

    let mut rng = OsRng::new().expect("Can't create random number generator");
    rng.fill_bytes(&mut keynum);

    let mut seed = [0; 32];
    rng.fill_bytes(&mut seed);
    let (mut skey, pkey) = ed25519::keypair(&seed);

    // Store private key
    let mut ctx = Sha512::new();
    ctx.input(&skey);
    let mut digest = [0; 64];
    ctx.result(&mut digest);
    let mut checksum = [0; 8];
    checksum.copy_from_slice(&digest[0..8]);

    let mut salt = [0; 16];
    rng.fill_bytes(&mut salt);

    let xorkey = kdf(&salt, kdfrounds, true, SECRETBYTES);

    for (prv, xor) in skey.iter_mut().zip(xorkey.iter()) {
        *prv = *prv ^ xor;
    }

    let private_key = PrivateKey {
        pkgalg: PKGALG,
        kdfalg: KDFALG,
        kdfrounds: kdfrounds,
        salt: salt,
        checksum: checksum,
        keynum: keynum,
        seckey: skey,
    };

    let mut out = vec![];
    private_key.write(&mut out).expect("Can't write to internal buffer");

    let priv_comment = format!("{} secret key", comment);
    write_base64_file(&privkey_path, &priv_comment, &out).unwrap();

    // Store public key
    let public_key = PublicKey::with_key_and_keynum(pkey, keynum);

    let mut out = vec![];
    public_key.write(&mut out).expect("Can't write to internal buffer");

    let pub_comment = format!("{} public key", comment);
    write_base64_file(&pubkey_path, &pub_comment, &out).unwrap();
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    if args.flag_V {
        verify(args.flag_p, args.flag_m, args.flag_x);
    } else if args.flag_G {
        let rounds = if args.flag_n { 0 } else { 42 };
        generate(args.flag_p, args.flag_s, args.flag_c, rounds);
    } else if args.flag_S {
        sign(args.flag_s, args.flag_m, args.flag_x);
    }
}
