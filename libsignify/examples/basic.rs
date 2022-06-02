//! Basic example that shows how to verify a signature of some file.
//!
//! You could, for example, replace the file reading with a HTTP client.
use libsignify::{Codeable, PublicKey, Signature};
use std::{fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("verifying signature of message file");

    // Boilerplate so this code can run both via `cargo test --doc` and `cargo run --example`.
    // Not relevant to the example otherwise.
    let base_path = if std::env::var("CARGO_CRATE_NAME").is_ok() {
        Path::new("./examples/")
    } else {
        Path::new("./libsignify/examples/")
    };

    // First, open the message to verify the validity of.
    let message = fs::read(base_path.join("message.txt"))?;

    // Then, get the public key of the signer.
    let (signer_id, _) = {
        let public_key_contents = fs::read_to_string(base_path.join("test_key.pub"))?;

        PublicKey::from_base64(&public_key_contents)?
    };

    // Now, fetch the signature we have for the message.
    //
    // This could be from anywhere trusted, including a HTTP server for example.
    let (signature, _) = {
        let signature_contents = fs::read_to_string(base_path.join("message.txt.sig"))?;
        Signature::from_base64(&signature_contents)?
    };

    // With all of the parts needed, the message can be checked now.
    match signer_id.verify(&message, &signature) {
        Ok(()) => {
            println!("message was verified!");
            Ok(())
        }
        Err(e) => {
            eprintln!("message did not verify: {}", e);
            Err(Box::new(e))
        }
    }
}
