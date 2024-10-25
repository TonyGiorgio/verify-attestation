use base64::{engine::general_purpose, Engine as _};
use nitro_enclave_attestation_document::AttestationDocument;
use reqwest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define the server endpoint
    let server_url = "https://enclave.secretgpt.ai/attestation";

    // Make an HTTP GET request to the server
    let client = reqwest::Client::new();
    let response = client.get(server_url).send().await?;

    // Check if the request was successful
    if !response.status().is_success() {
        eprintln!(
            "Failed to fetch attestation document: HTTP {}",
            response.status()
        );
        std::process::exit(1);
    }

    // Parse the JSON response
    let json_response: serde_json::Value = response.json().await?;

    // Extract the base64-encoded attestation document
    let attestation_doc_base64 = json_response["attestation_document"]
        .as_str()
        .ok_or("Attestation document not found in response")?;

    // Decode the base64 attestation document
    let document_data = general_purpose::STANDARD.decode(attestation_doc_base64)?;

    // Load the AWS Nitro Root Certificate
    // Note: You should securely obtain and store this certificate
    let trusted_root_certificate =
        include_bytes!("/Users/tony/Dev/Rust/verify-attestation/aws_root.der");

    // Authenticate and parse the attestation document
    match AttestationDocument::authenticate(&document_data, trusted_root_certificate) {
        Ok(doc) => {
            println!("Attestation document authenticated successfully!");

            // You can now access various fields of the attestation document
            println!("Module ID: {:?}", doc.module_id);
            println!("Digest: {:?}", doc.digest);
            println!("Timestamp: {}", doc.timestamp);

            // Add more fields as needed
        }
        Err(err) => {
            eprintln!("Failed to authenticate attestation document: {}", err);
            std::process::exit(1);
        }
    }

    Ok(())
}
