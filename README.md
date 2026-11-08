# ICS 344 Applied Cryptography Secure Exchange

This project implements a small secure message and file exchange prototype for the ICS 344 Information Security practical assignment.

The system simulates Alice and Bob communicating through an insecure channel where Eve may observe traffic and Mallory may modify transmitted data.

## Security Mechanisms

The prototype includes:

- AES-256-CBC encryption with PKCS7 padding
- AES-256-CTR encryption without padding
- Random IV generation for CBC
- Random nonce generation for CTR
- HMAC-SHA-256 integrity protection
- Finite-field Diffie-Hellman key establishment using 2048-bit parameters
- Separate AES and HMAC keys derived from the shared secret
- RSA-PSS digital signatures using RSA-2048 and SHA-256
- Controlled AES-CTR nonce-reuse misuse experiment
- Twelve security validation tests

## Project Structure

```text
ics344-applied-cryptography-secure-exchange/
├── evidence/
├── test_data/
│   └── unaligned_sample.txt
├── crypto_utils.py
├── key_exchange.py
├── main.py
├── misuse_experiment.py
├── signatures.py
├── tests.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10 or later
- Internet connection for installing dependencies
- The Python package listed in `requirements.txt`

## Installation

Clone the repository:

```powershell
git clone https://github.com/Wajza/ics344-applied-cryptography-secure-exchange.git
cd ics344-applied-cryptography-secure-exchange
```

Install the required package:

```powershell
python -m pip install -r requirements.txt
```

## Running the Integrated Workflow

Run a secure exchange using AES-CBC:

```powershell
python main.py --message "ICS344 secure exchange test" --mode CBC
```

Run a secure exchange using AES-CTR:

```powershell
python main.py --message "ICS344 secure exchange test" --mode CTR
```

Run the workflow using the unaligned test file:

```powershell
python main.py --file test_data\unaligned_sample.txt --mode CBC
```

The receiver verifies the HMAC and digital signature before decrypting the message.

## Running the Validation Tests

Run the complete test suite:

```powershell
python tests.py
```

The test suite contains twelve tests:

- T01: AES-CBC short-message round trip
- T02: AES-CBC unaligned-file round trip
- T03: AES-CTR short-message round trip
- T04: AES-CTR unaligned-file round trip
- T05: Valid HMAC verification
- T06: HMAC tamper detection
- T07: Diffie-Hellman key establishment
- T08: Valid digital-signature verification
- T09: Modified-message signature rejection
- T10: Repeated-message behaviour
- T11: Incorrect-key behaviour
- T12: AES-CTR nonce-reuse misuse

## Running the Misuse Experiment

Run the controlled AES-CTR nonce-reuse experiment:

```powershell
python misuse_experiment.py
```

The experiment compares correct encryption using fresh nonces, incorrect encryption using the same nonce with the same key, and corrected encryption using fresh nonces again. It demonstrates that nonce reuse exposes the XOR relationship between plaintexts.

## Evidence

The `evidence` folder contains the screenshots, outputs, logs, and diagrams used to support the technical report.

Evidence identifiers used in the report include:

- D01: Alice-Bob secure exchange DFD
- E01: Project structure
- E02: AES-CBC validation
- E03: AES-CTR validation
- E04: HMAC validation
- E05: Diffie-Hellman key establishment
- E06: Digital signatures
- E07: Integrated workflow
- E08: Validation inputs and results
- E09: CTR nonce-reuse experiment
- E10: Comparative security test suite

## Reproducibility

The implementation uses non-sensitive test messages and files. Each execution generates fresh cryptographic keys, IVs, nonces, and signatures.

Private keys, passwords, credentials, and sensitive personal data must not be committed to the repository.

## Academic Integrity and Responsible Use

This project is a controlled educational prototype. All adversarial tests are restricted to local project files and messages.

The implementation uses established cryptographic library primitives. AES, SHA-256, RSA, and Diffie-Hellman were not implemented from scratch.

The submitted implementation, experiments, and analysis should be reviewed and understood by the student before submission.

## Author

Wajd Alghamdi

Student ID: 202262140

## Repository

https://github.com/Wajza/ics344-applied-cryptography-secure-exchange
