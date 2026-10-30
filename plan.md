Project: SP Receive Card — BIP352 Silent Payments for Foundation Passport

You are an expert Rust developer and Bitcoin cryptography engineer.

Build a lightweight, offline-first Silent Payments Receive Card application for Foundation Passport using the Foundation app SDK.

1. Objective

Create a simple application that allows Passport users to:

Generate their own BIP352 Silent Payments identity.
Display their Silent Payment address as a QR code.
Create multiple labeled receiving addresses.
Save labels and settings securely on-device.
Export watch-only information for external wallets or accounting software.

The application must not send Bitcoin, construct transactions, or sign PSBTs in this first version.

Prioritize correctness, security, simplicity and compatibility with the Foundation SDK.

2. First: Inspect the SDK

Before implementing anything:

Inspect the available SDK documentation and example applications.
Identify the exact APIs for:
App seed access.
PIN authentication.
Private application storage.
QR code generation and scanning.
SlideToConfirm.
Clipboard or copy functionality, if supported.
Navigation and UI components.
Identify which Rust cryptography crates compile successfully on KeyOS.
Determine whether App seed access provides a stable derivation source across app reinstalls and device recovery.
Do not invent SDK APIs. Use actual documented interfaces.
Create a short implementation plan and identify any SDK limitations before coding.
3. Cryptographic implementation

Implement Bitcoin BIP352 Silent Payments according to the official specification.

Specification: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

Requirements:

Use the correct BIP352 key derivation paths and account structure.
Derive the scan and spend keys from the appropriate Passport seed material.
Implement the required elliptic curve operations using secp256k1.
Implement the BIP352 labeled receiving address mechanism.
Implement the required tagged hashing and point operations.
Encode addresses using the correct Silent Payments bech32m encoding.
Support the network parameters appropriate to the target environment.
Do not implement a simplified or custom Silent Payments scheme.

Important: Do not assume that arbitrary BIP32 derivation paths or key combinations are interchangeable with the BIP352 standard.

Use the official BIP352 test vectors from the beginning.

If a required feature cannot be implemented correctly, stop and document the limitation rather than introducing insecure workarounds.

4. Application features
A. First-launch setup

On first launch:

Display a brief explanation of Silent Payments.
Explain that the application derives a receiving identity from Passport seed material.
Request App seed access using the documented SDK permission flow.
Derive the required keys.
Never display or log secret keys during normal operation.
Store only the minimum necessary information.

Show a success screen confirming that the receiving identity has been generated.

B. Main screen

Display:

Application name: SP Receive Card.
Primary Silent Payment address.
QR code containing the address.
Copy address action, if supported.
Show full address action.
List of saved labels.
Button to create a new label.
Button to export watch-only information.

Use a clean, minimal Passport-native interface.

C. Labeled receiving addresses

Allow users to create multiple receiving labels.

Examples:

Personal
Donations
Business
Conference
Open-source contributions

For each label:

Accept a human-readable label name.
Derive the corresponding BIP352 labeled address.
Display its QR code.
Save the label and associated metadata in private application storage.
Allow the user to view, rename or delete the label.

Use the standard BIP352 labeling algorithm. Never generate unrelated keys for individual labels.

D. QR receiving screen

Create a dedicated screen for each receiving address.

Display:

Label name.
Silent Payment address.
Large QR code.
Copy address action.
Share/show QR action, using supported SDK functionality.

The QR must contain the exact address, with no additional text or formatting.

E. Watch-only export

Implement a dedicated watch-only export screen.

The export must contain the information required by a compatible Silent Payments scanning wallet:

Scan private key.
Spend public key.
Applicable network information.
Label metadata, where relevant.

Security requirements:

Require Passport PIN authentication.
Display an explicit warning explaining that the scan private key reveals incoming payment information.
Require SlideToConfirm before revealing or exporting secrets.
Keep the spend private key on Passport at all times.
Never write secret material to logs.
Never save exported secrets in ordinary application storage.
Clear temporary secret buffers when practical and supported.

Use a documented, interoperable export format. Do not invent a proprietary QR format and describe it as compatible with other wallets.

If the SDK cannot safely support the required export, document the limitation and implement the safest supported alternative.

5. UI and navigation

Use the Foundation UI kit.

Prefer existing components:

Card
Button
IconButton
Input
Dialog
Sheet
Toast
QR display functionality
PIN check
SlideToConfirm
Router

Suggested navigation:

Welcome / Setup
Home
Address Details
Create Label
Watch-only Export
Settings

Keep the number of screens minimal.

Use Foundation's theme and native UI conventions.

6. Storage

Use private application storage.

Persist:

User-created label names.
Label identifiers.
Application preferences.
Non-sensitive metadata needed to reconstruct addresses.

Avoid persisting private keys unless explicitly required by the documented seed/key management architecture.

Addresses should be reproducible from the underlying keys and BIP352 labeling information.

7. Testing

Testing is a critical part of this project.

Implement:

Official BIP352 test vectors.
Key derivation tests.
Address encoding and decoding tests.
Label derivation tests.
Mainnet and test-network tests where supported.
QR payload validation.
Persistence and recovery tests.
Watch-only export validation.

Verify generated addresses against an independent BIP352 implementation.

Do not declare the application complete merely because it compiles.

8. Security requirements
No network access required for normal operation.
No analytics or telemetry.
No private keys in application logs.
No hardcoded keys or test secrets in production.
No custom cryptographic primitives when established libraries are available.
Validate all user input.
Protect secret export behind PIN authentication.
Keep spend private keys on-device.
Clearly explain the security implications of exporting the scan private key.
9. Development approach

Work in incremental stages.

Stage 1: SDK inspection and compatibility assessment.

Stage 2: BIP352 cryptographic implementation and official test vectors.

Stage 3: Seed integration and key derivation.

Stage 4: Address generation and labeling.

Stage 5: QR interface and private storage.

Stage 6: Watch-only export.

Stage 7: Full testing and device validation.

After each stage:

Report what was implemented.
List files changed.
Report tests performed and their results.
Identify unresolved issues.
Do not silently skip requirements.
10. Definition of done

The application is complete when:

It builds successfully for Passport.
It derives keys correctly using the intended seed architecture.
It generates valid BIP352 addresses.
It creates valid labeled addresses.
QR codes contain valid receiving addresses.
Labels survive application restarts.
Watch-only exports are interoperable with a compatible external implementation.
Official BIP352 tests pass.
Secret material is handled safely.

Start by inspecting the SDK and producing the implementation plan. Then proceed with implementation.

Do not build PSBT signing, payment sending, transaction scanning, or blockchain synchronization in this version. Those are future features.