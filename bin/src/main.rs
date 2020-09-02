use anyhow::anyhow;
use anyhow::Result;
use argh::FromArgs;
use signify_lib::*;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::process;

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

fn bufwriter_from_file(filename: Option<String>) -> BufWriter<File> {
    BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filename.unwrap())
            .unwrap(),
    )
}

fn main() {
    let args: Args = argh::from_env();

    if args.verify {
        human(verify(
            BufReader::new(File::open(&args.public_key.unwrap()).unwrap()),
            {
                let signature_path = match args.signature_file {
                    Some(path) => path,
                    None => format!("{}.sig", args.message.clone().unwrap()),
                };

                BufReader::new(File::open(&signature_path).unwrap())
            },
            BufReader::new(File::open(&args.message.clone().unwrap()).unwrap()),
            args.embed,
        ));
    } else if args.generate {
        let kdfrounds_and_passphrase = if args.no_passphrase {
            None
        } else {
            Some((42.try_into().unwrap(), read_password(true).unwrap()))
        };
        human(generate(
            &mut bufwriter_from_file(args.public_key),
            &mut bufwriter_from_file(args.secret_key),
            args.comment,
            kdfrounds_and_passphrase,
        ));
    } else if args.sign {
        human(sign(
            BufReader::new(File::open(&args.secret_key.unwrap()).unwrap()),
            &{
                let mut msgfile = File::open(&args.message.clone().unwrap()).unwrap();
                let mut msg = vec![];
                msgfile.read_to_end(&mut msg).unwrap();
                msg
            },
            {
                let signature_file = match args.signature_file {
                    Some(path) => path,
                    None => format!("{}.sig", args.message.clone().unwrap()),
                };
                &mut bufwriter_from_file(Some(signature_file))
            },
            args.embed,
            read_password,
        ));
    }
}
