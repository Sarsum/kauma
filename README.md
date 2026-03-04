# Linus Fricke kauma
A modular Rust implementation of the Kauma exercise suite, focused on cryptographic primitives, finite field arithmetic, and cryptanalysis.

## Architecture Overview
The project is designed with a clear separation between the execution engine, the exercise logic, and the underlying mathematical primitives.
1. Entry Point (main.rs): Parses exercise JSON files into a TryAction enum.
2. Action Dispatcher (actions/): Deserializes action-specific arguments using serde and routes them to the appropriate logic.
3. Utility Core (utils/): Provides the mathematical backbone, including abstract Galois Field operations and polynomial arithmetic.

## Action Modules
The `actions/` directory contains the implementation for each specific exercise type. The root module handles the deserialization and dispatch logic.

| File | Description | Key Capabilities |
| --- | --- | --- |
| `calc.rs` | Basic Arithmetic | Implements standard operators (`+`, `-`, `*`, `/`) for initial test vectors. |
| `padding_oracle.rs` | Side-Channel Analysis | A specialized client that automates plaintext reconstruction via Padding Oracle attacks. |
| `gf_actions.rs` | Galois Field Ops | Interface for finite field arithmetic across two irreducible polynomials: `Mul`, `Pow`, `Inverse`, `Div`, `Sqrt`, `DivmMd` |
| `gfpoly_actions.rs` | GF Polynomials | Interface for advanced polynomial math: `Sort`, `Monic`, `Add`, `Mul`, `DivMod`, `GCD`, `Pow`, `PowMod`, `Diff`, `Sqrt`, `SFF`, `DDF` and `EDF`. |
| `gcm_actions.rs` | GCM Encryption & Cryptanalysis | Implements GCM authentication and leverages polynomial root-finding to exploit nonce reuse. |
| `rsa_factor.rs` | RSA Weakness Analysis | mplements prime factorization for public keys sharing common factors (Batch GCD). |

## Technical Utilities
The `utils/` directory provides the high-performance, abstract mathematical implementations used by multiple actions.

| File | Component | Technical Detail |
| --- | --- | --- |
| `gf.rs` | Galois Field Core | Implements abstract $GF(2^n)$ for two irreducable polynomials with operator overloading, allowing users to treat field elements as native Rust numbers. |
| `gf_poly.rs` | GF Polynomials | Built upon `gf.rs` to support polynomial arithmetic and modular exponentiation in finite fields. |
| `aes.rs` | GCM Utilities | Leverages polynomial math to do plain GCM encryption and solving for the authentication key ($H$) in cases of nonce reuse. |

## Tests
Tests are run using the RunTests.py script of my public test-vector repository, which also ships the collectively created testcases for the exercises.
The RunTests.py script is automatically being run on any push/PR to my private GitHub repository, resulting in an email in case any test fails.
The testcases includes at least all actions due for the upcoming submission and verifies the parsing of the values as well as the correct output.

## Unit Tests
The GitHub actions pipeline also includes some unit tests used to verify certain internal core functionalities.