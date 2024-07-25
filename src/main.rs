use ring::rand;
use ring::signature::{self, KeyPair, Ed25519KeyPair, Signature};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use base64;

#[derive(Serialize, Deserialize, Debug)]
struct Invoice {
    invoice_id: String,
    amount: f64,
    event_id: String,
    signature: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Receipt {
    receipt_id: String,
    amount: f64,
    transaction_id: String,
    invoice_id: String,
    signature: Option<String>,
}

fn generate_keys() -> (Ed25519KeyPair, Ed25519KeyPair) {
    let rng = rand::SystemRandom::new();
    let organizer_key = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let payment_gateway_key = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    (
        Ed25519KeyPair::from_pkcs8(organizer_key.as_ref()).unwrap(),
        Ed25519KeyPair::from_pkcs8(payment_gateway_key.as_ref()).unwrap(),
    )
}

fn sign_data(data: &[u8], key_pair: &Ed25519KeyPair) -> Signature {
    key_pair.sign(data)
}

fn verify_signature(data: &[u8], signature: &Signature, public_key: &[u8]) -> bool {
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
    peer_public_key.verify(data, signature.as_ref()).is_ok()
}

fn main() {
    // Generate keys for organizer and payment gateway
    let (organizer_key, payment_gateway_key) = generate_keys();

    // Organizer creates an invoice
    let invoice_id = Uuid::new_v4().to_string();
    let invoice = Invoice {
        invoice_id: invoice_id.clone(),
        amount: 100.0,
        event_id: "event_123".to_string(),
        signature: None,
    };

    // Serialize invoice and sign it
    let invoice_data = serde_json::to_string(&invoice).unwrap();
    let invoice_signature = sign_data(invoice_data.as_bytes(), &organizer_key);

    // Add signature to the invoice
    let mut signed_invoice = invoice;
    signed_invoice.signature = Some(base64::encode(invoice_signature.as_ref()));

    // Print the signed invoice
    println!("Signed Invoice: {:?}", signed_invoice);

    // User pays and payment gateway creates a receipt
    let receipt_id = Uuid::new_v4().to_string();
    let receipt = Receipt {
        receipt_id: receipt_id.clone(),
        amount: 100.0,
        transaction_id: Uuid::new_v4().to_string(),
        invoice_id: invoice_id.clone(),
        signature: None,
    };

    // Serialize receipt and sign it
    let receipt_data = serde_json::to_string(&receipt).unwrap();
    let receipt_signature = sign_data(receipt_data.as_bytes(), &payment_gateway_key);

    // Add signature to the receipt
    let mut signed_receipt = receipt;
    signed_receipt.signature = Some(base64::encode(receipt_signature.as_ref()));

    // Print the signed receipt
    println!("Signed Receipt: {:?}", signed_receipt);

    // Event organizer verifies the receipt
    let receipt_verified = verify_signature(
        receipt_data.as_bytes(),
        &receipt_signature,
        payment_gateway_key.public_key().as_ref(),
    );

    if receipt_verified {
        println!("Receipt verification successful.");
    } else {
        println!("Receipt verification failed.");
    }
}

