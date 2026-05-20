# Incentive: Target Security and Privacy Vision for the Encrypted Binary Archive

**Repository location:** `docs/Incentive.md`  
**Document status:** Aspirational target-state document; implementation-independent  
**Audience:** maintainers, reviewers, security auditors, advanced users, and contributors  
**Scope:** scientific, security, and product-goal documentation only; this document intentionally contains no source code, no concrete file-format schema, and no internal architecture description.  
**Interpretation note:** This document describes the intended target properties of the project. It should not be read as a claim that every property is already fully implemented, audited, benchmarked, or formally verified.

---

## Table of Contents

0. [Target-State Interpretation](#target-state-interpretation)
1. [Purpose](#1-purpose)
2. [Executive Summary](#2-executive-summary)
3. [Terminology](#3-terminology)
4. [Design Philosophy](#4-design-philosophy)
5. [Security Objectives](#5-security-objectives)
6. [Explicit Non-Goals](#6-explicit-non-goals)
7. [Threat Model](#7-threat-model)
8. [Security Claims and Their Conditions](#8-security-claims-and-their-conditions)
9. [Cryptographic Foundations](#9-cryptographic-foundations)
10. [Key Material Model](#10-key-material-model)
11. [Password and Keyfile Security](#11-password-and-keyfile-security)
12. [Metadata Privacy](#12-metadata-privacy)
13. [Size-Hiding and Its Limits](#13-size-hiding-and-its-limits)
14. [Integrity, Authenticity, and Failure Semantics](#14-integrity-authenticity-and-failure-semantics)
15. [Randomness Requirements](#15-randomness-requirements)
16. [Performance Model](#16-performance-model)
17. [Parallelism and Hardware Acceleration Principles](#17-parallelism-and-hardware-acceleration-principles)
18. [Correctness and Recovery Properties](#18-correctness-and-recovery-properties)
19. [Misuse Resistance and Safe Defaults](#19-misuse-resistance-and-safe-defaults)
20. [Operational Security Guidance](#20-operational-security-guidance)
21. [Testing and Validation Strategy](#21-testing-and-validation-strategy)
22. [Security Review Checklist](#22-security-review-checklist)
23. [Known Limitations](#23-known-limitations)
24. [Responsible Disclosure](#24-responsible-disclosure)
25. [Recommended Documentation Set](#25-recommended-documentation-set)
26. [References](#26-references)

---

## Target-State Interpretation

This document is written as an incentive and target-state specification. Its role is to describe the destination: the security posture, privacy guarantees, performance ambitions, engineering discipline, and validation standard that the project aims to achieve. Some statements are therefore intentionally framed as goals, requirements, or desired properties rather than as assertions about the current implementation.

Where the document uses phrases such as “the application is designed to,” “the system should,” or “the construction is intended to,” these should be interpreted as normative project goals unless a separate implementation-status document explicitly marks them as completed and verified.

---

## 1. Purpose

This document describes the target scientific and security rationale behind a high-performance encrypted binary archive application. The target application is intended to accept a directory tree, recursively protect its contents, and emit one or more binary output files with randomized names and the `.bin` extension. The target protected archive is intended to preserve the original directory structure, filenames, file contents, file sizes, and relevant metadata for later restoration, while preventing disclosure of those values to an observer who lacks the required secrets.

This incentive document is deliberately implementation-independent. It defines the desired security properties, the assumptions under which those properties hold, the cryptographic reasoning behind the design, the limits of what can and cannot be hidden, and the testing obligations necessary to support credible security claims.

This document does not specify concrete source code, class layouts, internal module boundaries, or a full binary file-format specification. Those details should be documented separately if the project chooses to expose them.

---

## 2. Executive Summary

The project aims to deliver a confidentiality- and integrity-preserving encrypted archive system for local or removable storage. Its security is based on modern, publicly analyzed cryptographic primitives rather than secrecy of implementation. The intended construction uses authenticated encryption, memory-hard key derivation, key separation, strong randomness, and a conservative leakage model.

The central security objective is simple: user data and sensitive metadata must enter an authenticated encrypted domain before being written to external storage. Public output files may reveal that encrypted data exists, and may reveal some coarse information about the total amount of protected data unless padding is enabled. They must not reveal original filenames, directory layout, individual file sizes, or file contents.

The target should not be described as literally or mathematically unbreakable. A scientifically precise claim is that, under standard assumptions about the selected cryptographic primitives and provided the passphrase and keyfiles have sufficient effective entropy, recovery of plaintext without the required secrets should be computationally infeasible with foreseeable resources.

The target design emphasizes the following principles:

- use authenticated encryption rather than encryption alone;
- treat metadata as sensitive data;
- derive cryptographic keys from both a passphrase and one or more binary keyfiles;
- use memory-hard password processing to resist large-scale guessing;
- enforce nonce uniqueness and domain separation;
- make tampering detectable;
- make unsafe modes difficult or impossible to use accidentally;
- preserve high throughput through streaming, batching, parallelism, and hardware acceleration where available;
- document leakage honestly rather than overstating privacy guarantees.

---

## 3. Terminology

### Archive

The protected logical representation of an input directory tree. The archive includes file contents, filenames, directory structure, and selected metadata required for restoration.

### Output File

A binary file emitted by the application. Output files use the `.bin` extension and randomized names. A single archive may be represented by one or more output files.

### Plaintext

Any user data or metadata before encryption, including file contents, filenames, paths, timestamps, permissions, file sizes, and directory relationships.

### Ciphertext

Encrypted and authenticated data written to output files. Ciphertext should not reveal the protected plaintext except through explicitly accepted leakage such as approximate total archive size.

### Associated Data

Data that is authenticated but not encrypted. Associated data may be public, but any change to it must cause authentication failure. Associated data must not include sensitive filenames, original file sizes, or user metadata.

### AEAD

Authenticated Encryption with Associated Data. AEAD schemes provide confidentiality for encrypted plaintext and integrity/authenticity for both encrypted plaintext and associated data.

### Passphrase

A human-memorable secret entered by the user. A passphrase may have lower entropy than a uniformly random cryptographic key and must therefore be processed through an appropriate password-based key derivation function.

### Keyfile

A binary file used as secret input to key derivation. A keyfile may be random data, a device-specific secret, or another file chosen by the user. Keyfiles must be treated as cryptographic secrets.

### KDF

Key Derivation Function. A mechanism that transforms passphrases, keyfiles, salts, and context strings into cryptographic keys.

### Salt

A non-secret random value used during key derivation to prevent precomputed attacks and ensure that identical passphrases do not produce identical derived values across archives.

### Nonce

A per-encryption value that must satisfy the uniqueness requirements of the selected AEAD scheme. Nonces are not necessarily secret, but nonce misuse can catastrophically weaken many encryption modes.

### Padding

Additional non-user data inserted before encryption or into the encrypted data stream to reduce information leakage from observable output sizes.

---

## 4. Design Philosophy

The project follows a conservative security philosophy: cryptographic design should minimize novelty, minimize implicit trust, and make security failures obvious. The application should be understandable to reviewers, testable under adversarial conditions, and explicit about its limitations.

### 4.1 Public Algorithms, Private Keys

The security of the system must not depend on hiding the algorithm, hiding the source code, or hiding the output format. A competent attacker should be assumed to know how the system works. The only unavailable values should be the user’s passphrase, the required keyfiles, and any ephemeral secrets that are not stored.

### 4.2 Authenticate Everything That Matters

Encryption without authentication is insufficient for an archive format. An attacker who can modify ciphertext must not be able to create predictable corruption, reorder protected material, splice data from one archive into another, or manipulate restoration behavior without detection. Authentication must cover the encrypted content and all public values that influence interpretation.

### 4.3 Metadata Is Sensitive

For many real-world datasets, filenames and directory structure can be nearly as sensitive as file contents. A filename may reveal a customer, patient, project name, legal matter, financial subject, or personal event. Therefore, metadata must be treated as plaintext requiring encryption, not as harmless container information.

### 4.4 Passwords Need Memory-Hard Processing

Human-chosen passphrases are often weaker than cryptographic keys. The system must assume that attackers may attempt offline guessing. A memory-hard password hashing or key derivation function raises the cost of each guess and reduces the efficiency advantage of specialized cracking hardware.

### 4.5 High Performance Must Not Weaken Security

The performance target is to avoid making cryptography the bottleneck relative to high-speed removable storage. This goal should be achieved through streaming, batching, parallelism, and vetted accelerated implementations, not by weakening KDF parameters, disabling authentication, shortening tags unsafely, reusing nonces, or exposing metadata.

### 4.6 Defaults Matter

Most users will rely on defaults. Secure defaults must therefore represent the intended security posture. Options that materially weaken security should be absent, clearly marked as dangerous, or restricted to testing builds.

---

## 5. Security Objectives

The application aims to provide the following properties.

### 5.1 Confidentiality of File Contents

Without the required passphrase and keyfiles, an attacker in possession of the `.bin` output files should not be able to recover plaintext file contents.

### 5.2 Confidentiality of Filenames and Paths

Original filenames, relative paths, directory names, and directory hierarchy should be protected as encrypted metadata. Output filenames must be random or otherwise non-semantic.

### 5.3 Confidentiality of Individual File Sizes

The size of each original file should not be visible from the external output structure. Individual file sizes may be stored internally, but only inside the authenticated encrypted domain.

### 5.4 Integrity of Contents and Metadata

Unauthorized modification, deletion, truncation, substitution, or reordering of protected data should be detected with overwhelming probability during decryption or restoration.

### 5.5 Authentication of Archive Interpretation

All public or semi-public values that influence how ciphertext is interpreted must be authenticated. A manipulated interpretation context must not cause silent acceptance of attacker-controlled plaintext.

### 5.6 Robust Failure Behavior

Incorrect secrets, corrupted data, missing output files, unsupported format versions, and tampering attempts should fail safely. Failure should not expose partial plaintext, cause unsafe filesystem writes, or reveal unnecessary diagnostic information to an attacker.

### 5.7 Performance Compatibility with High-Speed Storage

The application should be engineered so that cryptographic processing does not fall below the practical throughput of common USB 3.2 storage devices on supported hardware, subject to the physical limits of the host, device, filesystem, and operating system.

---

## 6. Explicit Non-Goals

A rigorous security document must state what is not promised.

### 6.1 Perfect Deniability

The output files may look like random binary data, but the system does not guarantee plausible deniability. A forensic observer may infer that the files are encrypted archives.

### 6.2 Perfect Total-Size Hiding Without Padding

The system cannot hide the approximate total amount of encrypted data unless padding is used. Even with padding, the padded size remains observable.

### 6.3 Protection Against Compromised Endpoints

If the machine performing encryption or decryption is compromised, malware may capture passphrases, keyfiles, plaintext, or derived keys. Cryptography at rest cannot compensate for a hostile execution environment.

### 6.4 Protection Against User Disclosure

If the user reveals the passphrase and keyfiles, the system cannot preserve confidentiality.

### 6.5 Protection Against Weak Passphrases Alone

If no high-entropy keyfile is used and the passphrase is weak, an offline attacker may eventually guess it despite memory-hard derivation. The KDF increases cost; it does not create entropy that was never present.

### 6.6 Infinite Backward Compatibility

Old formats may need migration if cryptographic guidance changes. Compatibility should be balanced against long-term security.

### 6.7 Malware-Resistant Restoration

The system can validate archive authenticity, but it cannot guarantee that restored files are safe to open. Restored executables, scripts, documents, or archives may themselves be malicious if they were malicious before encryption.

---

## 7. Threat Model

### 7.1 Attacker Capabilities

The attacker may:

- obtain all output `.bin` files;
- know the software name, version, source code, algorithms, and documentation;
- perform unlimited offline analysis of the output files;
- attempt passphrase guessing;
- possess some but not all keyfiles;
- modify, delete, truncate, duplicate, or reorder output files;
- replace output files with files from another archive;
- observe output file sizes, file counts, timestamps, and storage locations;
- compare multiple archives produced by the same user;
- exploit implementation bugs if present.

### 7.2 Attacker Limitations

The security claims assume the attacker cannot:

- break the underlying cryptographic primitives beyond their accepted security bounds;
- obtain the correct passphrase;
- obtain all required keyfiles;
- compromise the host during encryption or decryption;
- bypass authentication checks through implementation defects;
- force the application to operate in an intentionally weakened mode.

### 7.3 Assets Protected

The primary protected assets are:

- file contents;
- original filenames;
- relative paths;
- directory structure;
- individual file sizes;
- selected metadata required for restoration;
- cryptographic keys and derived secrets;
- relationships between encrypted chunks and original files.

### 7.4 Observable Leakage

The attacker may still observe:

- number of output files;
- total encrypted size, possibly rounded by padding;
- output file creation and modification times from the host filesystem;
- approximate encryption activity timing if they observe the machine;
- whether two archives are byte-identical, which should be prevented by fresh salts and randomness;
- software-specific public headers if the format includes identifiable magic or version data.

The leakage model should be documented clearly so that users can choose padding and operational practices appropriate to their risk.

---

## 8. Security Claims and Their Conditions

### 8.1 Practical Unrecoverability Claim

The intended security claim is:

> Given output files produced by the application, and assuming correct implementation, strong cryptographic primitives, unique nonces, sufficient passphrase entropy, and possession of fewer than all required keyfiles, recovery of protected plaintext should be computationally infeasible with foreseeable resources.

This claim is conditional. It does not hold if the passphrase is guessable, keyfiles are available to the attacker, nonces are reused in a way that violates the AEAD security model, authentication failures are ignored, or the implementation leaks secrets.

### 8.2 Integrity Claim

The system should reject unauthorized modifications to encrypted content, protected metadata, and authenticated public interpretation data with probability overwhelmingly close to one. This claim depends on using AEAD with a sufficiently strong authentication tag and enforcing failure semantics correctly.

### 8.3 Metadata Confidentiality Claim

The system should not expose original filenames, paths, individual file sizes, or directory hierarchy in plaintext output. This claim depends on treating metadata as encrypted payload rather than public container data.

### 8.4 Size-Hiding Claim

The system should hide individual file sizes by preventing alignment between external ciphertext boundaries and original file boundaries. Total archive size privacy is only as strong as the selected padding policy.

### 8.5 Performance Claim

The application should be capable of throughput compatible with practical USB 3.2 storage speeds on suitable hardware. This is an engineering claim, not a cryptographic proof. It must be supported by reproducible benchmarks across representative devices, operating systems, filesystems, input data distributions, and CPU capabilities.

---

## 9. Cryptographic Foundations

### 9.1 Authenticated Encryption

Authenticated encryption is the core primitive for protecting archive chunks or records. AEAD modes provide confidentiality and integrity in a single construction. This is essential because archive data is long-lived, attacker-modifiable, and restored into a filesystem environment where silent corruption can be dangerous.

Acceptable AEAD families include:

- XChaCha20-Poly1305, where available from a vetted cryptographic library;
- ChaCha20-Poly1305 in contexts where nonce management is strictly controlled;
- AES-256-GCM on platforms with reliable hardware acceleration and correct nonce handling.

The documentation should not imply that all AEAD modes are interchangeable. Each mode has specific nonce requirements, message limits, tag handling rules, and implementation concerns.

### 9.2 XChaCha20-Poly1305

XChaCha20-Poly1305 is attractive for file encryption because it extends the nonce size compared with standard ChaCha20-Poly1305. A larger nonce space reduces accidental nonce-collision risk when nonces are randomly generated, though uniqueness remains mandatory under a given key. This property is useful in systems that encrypt many independent units or operate concurrently.

XChaCha20-Poly1305 should still be treated as a precise cryptographic construction, not as a license for careless design. Nonces must be generated or derived according to a documented, testable rule. The same key and nonce pair must never be reused for distinct plaintexts.

### 9.3 AES-GCM

AES-GCM is a widely deployed authenticated encryption mode and can be extremely fast on CPUs with AES and carryless multiplication acceleration. Its security is highly sensitive to nonce uniqueness. Reusing a GCM nonce with the same key can have catastrophic consequences, potentially compromising confidentiality and authentication.

AES-GCM should therefore be enabled only when the implementation can guarantee nonce uniqueness across all encrypted units under the same key, including parallel execution and multi-file output.

### 9.4 Password-Based Key Derivation

Passphrases should never be used directly as encryption keys. A password-based KDF must be used to transform the passphrase into high-quality key material while making offline guessing expensive.

A suitable KDF should be memory-hard, tunable, salted, and parameterized in a way that supports future migration. Argon2id is the preferred family for modern password hashing and password-based derivation because it combines defenses against side-channel and GPU/ASIC-accelerated cracking strategies more effectively than older CPU-only KDFs.

The selected KDF parameters should be stored in the public part of the archive because decryption requires them. These parameters are not secret. They must, however, be authenticated so that an attacker cannot silently downgrade them for interpretation or migration logic.

### 9.5 Keyfile Contribution

A keyfile contributes machine-readable entropy or secret material. The effective security of the system can be much higher when a strong keyfile is required in addition to a passphrase. This supports a two-factor-like model: something the user knows and something the user has.

A keyfile must be processed in a way that commits to its complete byte content. Partial reads, filename-only references, metadata-only references, or platform-dependent text transformations are unacceptable. Binary transparency is essential.

### 9.6 Key Separation

A single derived master secret should not be reused directly for multiple purposes. Separate subkeys should be derived for logically distinct roles, such as content encryption, metadata protection, header authentication, nonce derivation, and integrity verification.

Key separation limits damage from cross-protocol interactions and simplifies review. It also makes future format evolution safer because new roles can be assigned new derivation contexts.

### 9.7 Domain Separation

All derivations and authenticated contexts should include clear domain labels. Domain separation prevents accidental reuse of derived values across different roles, versions, algorithms, or project components.

Domain labels should be stable, versioned, and specific. They should distinguish archive encryption from metadata encryption, test vectors, migration tools, and any future related protocols.

### 9.8 Hashing

Cryptographic hashing is needed for purposes such as keyfile commitment, integrity pre-processing, optional manifests, and test vectors. Hashes used in security-sensitive contexts should be modern, collision-resistant, and implemented by vetted libraries.

BLAKE3 is particularly useful for large local inputs because it is designed for high parallelism and efficient SIMD execution. When used, its role should be documented precisely: ordinary hashing, keyed hashing, derivation, or extendable output. These roles should not be confused.

---

## 10. Key Material Model

### 10.1 Inputs to Key Establishment

The security of the archive is based on a combination of:

- the user’s passphrase;
- one or more keyfiles;
- a per-archive salt;
- a per-archive random identifier or equivalent context;
- algorithm and version context;
- KDF parameters.

The passphrase provides memorized secrecy. Keyfiles provide binary secrecy. Salts and archive context ensure uniqueness and prevent cross-archive equality.

### 10.2 Entropy Considerations

A uniformly random 256-bit keyfile can provide extremely high entropy if kept secret. A human passphrase may provide much less. Combining both allows the system to remain strong even if one component is weaker than ideal, provided the attacker does not possess enough information to guess or reconstruct the combined input.

However, keyfiles should not be assumed random merely because they are large. A public ISO image, common executable, downloaded media file, or publicly known document is not a secret keyfile. A keyfile that an attacker can obtain or predict contributes no meaningful secrecy.

### 10.3 Required Secret Completeness

The intended model is all-or-nothing with respect to configured secrets: the correct passphrase and all required keyfiles are needed. Possession of only a subset should not allow partial decryption, metadata recovery, or reliable verification of guesses beyond ordinary authentication failure.

### 10.4 Key Lifecycle

Derived keys should exist only as long as necessary. They should not be logged, serialized, swapped to disk where avoidable, included in crash reports, exposed through diagnostics, or retained after operation completion.

The implementation should use platform-appropriate memory-protection and zeroization mechanisms. These mechanisms are defense-in-depth; they do not protect against a fully compromised host, but they reduce accidental leakage.

---

## 11. Password and Keyfile Security

### 11.1 Passphrase Requirements

Users should be encouraged to use long, high-entropy passphrases. Length alone is not sufficient if the phrase is predictable. Recommended passphrases are generated from random words or a password manager and should not be reused across unrelated systems.

A passphrase intended to protect valuable long-term archives should resist offline guessing. Short passwords, dictionary words, keyboard patterns, personal names, dates, and reused account passwords are inappropriate.

### 11.2 Keyfile Requirements

Recommended keyfiles should be generated from cryptographically secure randomness or another source with comparable secrecy. They should be backed up securely and stored separately from encrypted archives.

A keyfile should not be:

- a public file;
- a file synchronized to untrusted cloud storage without additional protection;
- a file likely to be modified by applications;
- a text file subject to newline or encoding conversion;
- a file embedded inside the encrypted archive it protects;
- the same file reused casually across unrelated threat domains without consideration.

### 11.3 Loss and Recovery

If the passphrase or any required keyfile is lost, recovery should be computationally infeasible by design. This is a feature, not a bug. Users must understand that there is no backdoor, master recovery key, support override, or safe way to bypass missing secrets.

### 11.4 Rotation

Key rotation means decrypting with old secrets and re-encrypting with new secrets. The system should not imply that changing a passphrase can magically re-secure already-exposed archives unless the archive is actually rewrapped or re-encrypted according to a documented secure process.

### 11.5 Compromise Response

If a passphrase or keyfile is suspected compromised, existing archives protected by that secret should be considered at risk. The correct response is to create new archives under fresh secrets and, where appropriate, securely destroy old vulnerable copies.

---

## 12. Metadata Privacy

### 12.1 Metadata Treated as Plaintext

The archive must treat the following as sensitive:

- filenames;
- extensions;
- directory names;
- relative paths;
- symlink targets, if supported;
- file sizes;
- file ordering;
- timestamps;
- permissions;
- ownership identifiers, if preserved;
- file type information;
- archive comments or labels;
- application-specific restoration hints.

These values should be protected inside the authenticated encrypted domain unless the user explicitly chooses to expose them.

### 12.2 Why Metadata Matters

Metadata can reveal substantial private information. For example, a filename can disclose a client name, medical condition, legal issue, financial event, or project codename. A directory tree can reveal business processes or personal history. Individual file sizes can identify known files by comparison with public datasets.

### 12.3 Output Naming

Output filenames should be generated from sufficient randomness and should not encode original names, counts, dates, machine identifiers, user identifiers, content hashes, or ordering information unless such information is intentionally public and authenticated.

### 12.4 Metadata Integrity

Metadata must not merely be encrypted; it must also be authenticated. A malicious change to a restored path or file type can be more dangerous than corruption of file bytes. The restoration process must reject metadata tampering.

---

## 13. Size-Hiding and Its Limits

### 13.1 Individual File Size Hiding

The system should avoid exposing a direct mapping between original files and external ciphertext regions. If a visible output segment corresponds exactly to one input file, the size of that file leaks. Therefore, original file boundaries should be hidden within the encrypted representation.

### 13.2 Total Size Leakage

The total encrypted output size is observable. Even if the archive uses encryption perfectly, an observer can estimate the amount of protected data unless padding is applied. This is a fundamental limitation of storage encryption systems.

### 13.3 Padding Strategies

Padding can reduce size leakage, but it has a cost. Reasonable conceptual strategies include:

- padding only to an encryption unit boundary;
- padding to a coarse size class;
- padding to the next power of two;
- padding to a configured fixed container size;
- adding cover output files to obscure file counts;
- periodically repacking archives to reduce correlation across versions.

No padding strategy is universally optimal. Stronger privacy consumes more storage and may increase write time.

### 13.4 Traffic Analysis Across Versions

If an attacker observes multiple versions of an archive over time, they may infer changes from size differences, timestamps, or output file churn. Padding reduces but does not eliminate this risk. Version-to-version privacy requires careful operational discipline and may require fixed-size containers or regular re-randomization.

### 13.5 Compression and Length Leakage

Compression can improve performance and reduce storage usage, but it interacts with size privacy. If an attacker can influence plaintext and observe compressed encrypted lengths, compression can create side channels. For local archival use, compression may be acceptable when the input is fully controlled by the user. For adversarially influenced input, compression should be conservative or disabled.

---

## 14. Integrity, Authenticity, and Failure Semantics

### 14.1 Authentication Failure

Authentication failure must be treated as a security event. The application should not attempt best-effort recovery of unauthenticated plaintext by default. Continuing after authentication failure risks restoring attacker-manipulated data.

### 14.2 Error Message Discipline

Error messages should be useful but not overly revealing. For example, an authentication failure may result from an incorrect passphrase, missing keyfile, corrupted data, wrong archive, or tampering. The application should avoid giving attackers an oracle that distinguishes these cases in a way that accelerates guessing.

### 14.3 Atomic Restoration

Restoration should avoid leaving ambiguous partially restored states. Where possible, output should be written to temporary locations and committed only after the relevant authenticated data has been validated. If full atomic restoration is impossible for very large archives, partial results must be clearly marked as incomplete and unsafe to trust.

### 14.4 Filesystem Safety

Restoration must not allow archive metadata to escape the chosen output directory. Absolute paths, parent-directory traversal, platform-specific device paths, reserved names, and unsafe symlink behavior must be controlled. This is a security property independent of cryptographic strength.

### 14.5 Truncation and Reordering

The format should make truncation, missing segments, duplicated segments, and reordering detectable. A successful decryption must mean not merely that some chunks authenticated individually, but that the archive as a whole is complete and coherent according to authenticated metadata.

---

## 15. Randomness Requirements

### 15.1 Cryptographically Secure Randomness

The application must use the operating system’s cryptographically secure random number generator or a vetted cryptographic library that obtains entropy from the operating system. Non-cryptographic pseudorandom generators are unacceptable for salts, archive identifiers, output names, nonces where random nonces are used, or generated keyfiles.

### 15.2 Uniqueness Versus Unpredictability

Some values must be unpredictable; others need only be unique. Salts and output names should be random enough to avoid collisions and correlations. Nonces must satisfy the selected AEAD scheme’s uniqueness requirement. If random nonces are used, the nonce space must be large enough that collision probability is negligible for the expected number of encryptions.

### 15.3 Randomized Output Names

Random output names should have enough entropy to make collision and guessing negligible. They should not be derived from plaintext content, user identity, timestamps alone, or deterministic counters visible to observers.

### 15.4 Failure of Randomness

A failure in randomness can compromise security silently. The application should fail closed if secure randomness is unavailable. It should not fall back to time-based seeds, process identifiers, standard library pseudo-random functions, or deterministic development defaults.

---

## 16. Performance Model

### 16.1 Throughput Target

The performance target is to keep encryption and decryption from becoming slower than the practical read/write speed of high-speed USB 3.2 storage. USB 3.2 includes nominal transfer rates of 5 Gbps, 10 Gbps, and 20 Gbps, but real-world storage throughput depends on device quality, flash behavior, controller design, filesystem overhead, host controller performance, thermal throttling, and workload shape.

The application should therefore measure practical throughput rather than rely only on theoretical bus rates.

### 16.2 Streaming Requirement

Large archives should be processed in a streaming manner. The application should not require loading the entire input tree, all file contents, or the entire output archive into memory. Streaming protects scalability and reduces memory pressure.

### 16.3 Workload Diversity

Benchmarking must include multiple workload classes:

- one very large file;
- many small files;
- deeply nested directory trees;
- incompressible random-like data;
- compressible text-like data, if compression is supported;
- cold-cache and warm-cache runs;
- internal SSD source to USB target;
- USB source to internal SSD target;
- same-device read/write scenarios.

### 16.4 Separating Bottlenecks

A rigorous benchmark should separately estimate:

- raw read throughput;
- raw write throughput;
- encryption throughput on memory-resident data;
- decryption throughput on memory-resident data;
- keyfile hashing time;
- KDF latency;
- metadata processing cost;
- end-to-end archive creation time;
- end-to-end restoration time.

Without separating these components, it is easy to misattribute storage limitations to cryptography or cryptographic overhead to storage.

### 16.5 KDF Latency Is Different from Streaming Throughput

Password-based key derivation is intentionally expensive. It should add a bounded startup cost, not reduce per-gigabyte streaming throughput. This distinction should be clear in user documentation: strong KDF settings may make archive opening take seconds, while bulk encryption remains fast afterward.

### 16.6 Thermal and Sustained Write Behavior

USB flash devices and portable SSDs may advertise high peak speeds but throttle during sustained writes. Benchmark claims should distinguish peak throughput from sustained throughput over realistic archive sizes.

---

## 17. Parallelism and Hardware Acceleration Principles

### 17.1 Safe Parallelism

Parallelism is acceptable only when it preserves cryptographic invariants. Concurrent encryption must not introduce nonce reuse, key reuse across incompatible domains, nondeterministic metadata races, or output ordering ambiguity.

### 17.2 CPU Acceleration

Modern CPUs commonly provide acceleration for AES, polynomial multiplication, vectorized stream ciphers, and high-speed hashing. The application may use such acceleration through vetted cryptographic libraries or well-reviewed backends. Feature detection must be correct and conservative.

### 17.3 SIMD

SIMD can improve throughput by processing multiple blocks or independent units in parallel. SIMD usage must not change cryptographic outputs, weaken constant-time behavior where relevant, or introduce platform-specific correctness differences.

### 17.4 GPU Acceleration

GPU acceleration may be beneficial for some workloads but is not automatically superior. Data transfer overhead, batching latency, driver behavior, memory pressure, and side-channel considerations can offset raw compute advantages. GPU paths must meet the same correctness and authentication requirements as CPU paths.

### 17.5 Determinism of Results

Hardware acceleration should not change the logical archive contents except for intentional fresh randomness. Different hardware backends should be interoperable and should produce decryptable archives according to the same documented format rules.

---

## 18. Correctness and Recovery Properties

### 18.1 Exact Restoration

Given the correct secrets and unmodified output files, restoration should reproduce the protected directory tree according to the selected metadata preservation policy. If some metadata cannot be restored on a target platform, the limitation should be explicit.

### 18.2 Cross-Platform Path Semantics

Different operating systems treat paths, Unicode normalization, reserved names, permissions, and symbolic links differently. The archive should define restoration behavior carefully enough that cross-platform use is predictable and safe.

### 18.3 Empty Files and Empty Directories

Empty files and empty directories must be represented intentionally. They should not disappear merely because they contain no file bytes.

### 18.4 Special Files

Device files, named pipes, sockets, reparse points, symlinks, hard links, sparse files, extended attributes, and alternate data streams require explicit policy. Unsupported types should fail clearly or be skipped only under an explicit user-selected policy.

### 18.5 Partial Damage

The default security posture should reject damaged archives. Optional salvage tooling, if ever provided, should be clearly separated from normal restoration and should never claim authenticity for unauthenticated material.

---

## 19. Misuse Resistance and Safe Defaults

### 19.1 Unsafe Options Should Not Be Normal Options

The following behaviors should not be available in ordinary production use:

- encryption without authentication;
- accepting truncated authentication tags below the selected scheme’s safe level;
- disabling KDF processing for passphrase-based archives;
- storing filenames or file sizes in plaintext;
- deterministic output without a documented expert mode;
- ignoring authentication failures;
- falling back to weak randomness;
- reusing a nonce with the same key.

### 19.2 Versioning and Algorithm Agility

The archive format should support versioning and future migration. Algorithm agility must be designed carefully: supporting many algorithms can increase attack surface. The project should prefer a small number of strong, well-reviewed suites over a large menu of exotic choices.

### 19.3 Downgrade Resistance

An attacker should not be able to modify public parameters to force weaker interpretation. Version identifiers, algorithm identifiers, KDF parameters, and other interpretation-critical values must be authenticated.

### 19.4 Fail-Closed Behavior

When required information is missing, unsupported, corrupted, or unauthenticated, the application should fail closed. It should not attempt insecure fallback behavior.

---

## 20. Operational Security Guidance

### 20.1 Recommended User Practices

Users should:

- choose long, high-entropy passphrases;
- use at least one high-entropy secret keyfile for important archives;
- store keyfiles separately from encrypted output files;
- maintain offline backups of keyfiles;
- test restoration before relying on an archive for long-term storage;
- use padding when output size privacy matters;
- avoid decrypting sensitive archives on untrusted machines;
- securely delete plaintext staging copies where appropriate;
- understand that lost secrets mean lost data.

### 20.2 Keyfile Backup Strategy

A keyfile backup should be protected at least as strongly as the encrypted archive. Multiple copies may be necessary for availability, but each copy increases exposure. A good strategy separates encrypted archives, passphrase records, and keyfiles across different physical or administrative locations.

### 20.3 Passphrase Storage

For high-value data, users should consider storing passphrases in a reputable password manager or other secure secret-management system. Human memory alone is vulnerable to forgetting, while unprotected notes are vulnerable to disclosure.

### 20.4 Cloud Storage

Encrypted output files can be stored in cloud storage, but cloud storage may reveal timestamps, file sizes, file counts, access patterns, IP addresses, account identity, and version history. Padding and operational discipline may be required for stronger privacy.

### 20.5 Shared Archives

Sharing encrypted archives requires sharing the necessary secrets. This should be done through secure channels. Sending the archive and its keyfile through the same compromised channel may defeat the security model.

---

## 21. Testing and Validation Strategy

### 21.1 Cryptographic Test Vectors

The project should maintain test vectors for supported cryptographic suites and archive-level behavior. Test vectors should include successful encryption/decryption cases, authentication failures, wrong passphrases, wrong keyfiles, corrupted headers, corrupted ciphertext, and truncated output.

### 21.2 Property-Based Testing

Property-based tests should verify high-level invariants, such as:

- decrypting a valid archive with correct secrets restores the original data;
- any single-bit modification to authenticated data causes failure;
- randomized output names do not reveal input names;
- individual file sizes are not externally represented as visible segment sizes;
- restoration never writes outside the selected output directory;
- unsupported metadata is handled according to documented policy.

### 21.3 Fuzzing

Archive parsing and restoration logic should be fuzzed aggressively. The most important fuzzing targets are public input parsing, encrypted container interpretation after authentication, path handling, metadata decoding, and error handling.

### 21.4 Fault Injection

The test suite should simulate:

- interrupted writes;
- missing output files;
- duplicated output files;
- reordered output files;
- wrong format versions;
- unsupported algorithm identifiers;
- corrupted salts or parameters;
- disk-full conditions;
- permission errors;
- malformed paths;
- symlink attacks during restoration.

### 21.5 Performance Regression Testing

Performance tests should be reproducible and should record hardware, operating system, filesystem, input dataset, storage device, cache state, KDF parameters, and cryptographic suite. The goal is not merely to produce impressive numbers, but to prevent regressions and identify bottlenecks honestly.

### 21.6 Independent Review

Cryptographic software benefits from independent review. The project should encourage review of threat model, parameter choices, error handling, randomness, nonce handling, key lifecycle, and restore safety.

---

## 22. Security Review Checklist

Before a release, reviewers should verify at least the following.

### Cryptographic Configuration

- Are only approved modern cryptographic primitives enabled by default?
- Is authenticated encryption mandatory?
- Are authentication tags checked before plaintext is trusted?
- Are nonces guaranteed unique under each key?
- Are KDF parameters strong enough for the intended release profile?
- Are salts generated with cryptographically secure randomness?
- Are derived keys separated by purpose?
- Are public interpretation parameters authenticated?

### Metadata Protection

- Are filenames encrypted?
- Are paths encrypted?
- Are individual file sizes hidden from the external structure?
- Are timestamps and permissions protected or intentionally excluded?
- Are output filenames non-semantic and randomly generated?

### Restore Safety

- Is path traversal impossible?
- Are absolute paths rejected or sanitized?
- Are unsafe symlink behaviors controlled?
- Are partially restored outputs handled safely?
- Are special files governed by explicit policy?

### Secret Handling

- Are passphrases never logged?
- Are keyfiles read as binary data?
- Are derived keys cleared after use?
- Are error messages resistant to oracle behavior?
- Are crash reports prevented from exposing secrets where possible?

### Robustness

- Are corrupted archives rejected?
- Are missing segments detected?
- Are unsupported versions handled safely?
- Are downgrade attempts detected?
- Are fuzzing and fault-injection tests part of release validation?

---

## 23. Known Limitations

Because this is an incentive document, “known limitations” include both unavoidable theoretical limits and practical implementation obligations that must be verified before strong release claims are made. A separate implementation-status or audit document should eventually distinguish between target properties, implemented properties, tested properties, and independently reviewed properties.


### 23.1 No Absolute Security

No software can honestly promise absolute unbreakability. Security depends on correct implementation, strong primitives, strong secrets, safe defaults, and a trustworthy execution environment.

### 23.2 Side Channels

The system may leak information through timing, storage access patterns, power consumption, CPU cache behavior, or operating system telemetry. These channels are generally outside the scope of ordinary local archive encryption, but they may matter for high-assurance environments.

### 23.3 Endpoint Exposure

Plaintext exists before encryption and after decryption. During those moments it is vulnerable to malware, compromised kernels, malicious peripherals, memory scraping, screen capture, keyboard logging, and insecure temporary files.

### 23.4 Human Factors

Users may lose passphrases, overwrite keyfiles, choose weak secrets, store secrets next to ciphertext, or decrypt archives on unsafe machines. Good documentation and safe defaults reduce but do not eliminate these risks.

### 23.5 Long-Term Cryptographic Change

Cryptographic recommendations evolve. The project should expect future migration needs and should not assume today’s best choices will remain optimal indefinitely.

---

## 24. Responsible Disclosure

Security vulnerabilities should be reported privately through the project’s documented security contact or repository security advisory mechanism. Reports should include enough detail to reproduce the issue, affected versions, expected impact, and any known mitigations.

The project should publish a clear policy for:

- supported versions;
- expected response time;
- coordinated disclosure timeline;
- crediting reporters;
- handling suspected data-loss or key-exposure vulnerabilities;
- issuing patched releases and migration guidance.

---

## 25. Recommended Documentation Set

This file should be one part of a broader `docs/` directory. Recommended companion documents include:

- `docs/user_guide.md` — user-facing encryption and decryption guide;
- `docs/threat_model.md` — expanded adversary and leakage analysis;
- `docs/security_policy.md` — supported versions and disclosure process;
- `docs/recovery_and_backups.md` — passphrase and keyfile backup guidance;
- `docs/benchmarking.md` — reproducible performance methodology;
- `docs/format_overview.md` — high-level, non-secret format overview;
- `docs/release_checklist.md` — security and correctness gates before release;
- `docs/faq.md` — common user questions and misconceptions.

---

## 26. References

The following references are relevant to the scientific basis of this document. They are listed for maintainers and reviewers; the project should prefer primary sources and vetted library documentation when making security decisions.

1. Y. Nir and A. Langley, **RFC 8439: ChaCha20 and Poly1305 for IETF Protocols**, IETF, 2018.  
   https://www.rfc-editor.org/rfc/rfc8439.html

2. H. Krawczyk and P. Eronen, **RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)**, IETF, 2010.  
   https://datatracker.ietf.org/doc/html/rfc5869

3. A. Biryukov, D. Dinu, D. Khovratovich, and S. Josefsson, **RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications**, IETF, 2021.  
   https://datatracker.ietf.org/doc/rfc9106/

4. M. Dworkin, **NIST Special Publication 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC**, NIST, 2007.  
   https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf

5. NIST, **Announcement of Proposal to Revise SP 800-38D**, 2023.  
   https://csrc.nist.gov/News/2023/proposal-to-revise-sp-800-38d

6. libsodium documentation, **XChaCha20-Poly1305 construction**.  
   https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction

7. BLAKE3 Team, **Official Rust and C implementations of BLAKE3**.  
   https://github.com/BLAKE3-team/BLAKE3

8. USB Implementers Forum, **USB 3.2 Specification Overview**.  
   https://www.usb.org/usb-32-0

9. OWASP Cheat Sheet Series, **Key Management Cheat Sheet**.  
   https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

10. OWASP Cheat Sheet Series, **Cryptographic Storage Cheat Sheet**.  
    https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

---

## Appendix A: Suggested Repository Header

Suggested one-paragraph description for the repository documentation index:

> This project provides a high-performance encrypted binary archive format for recursively protecting directory trees. It is designed to preserve and restore filenames, paths, file contents, and selected metadata while keeping them confidential inside authenticated encryption. Security relies on modern public cryptographic primitives, memory-hard passphrase processing, optional high-entropy keyfiles, strict authentication, and conservative handling of metadata and size leakage.

---

## Appendix B: Plain-Language Security Statement

A suitable user-facing summary is:

> If you use a strong passphrase and keep all required keyfiles secret, the encrypted `.bin` files should be computationally infeasible to decrypt without those secrets. The archive also protects filenames and individual file sizes. However, anyone who sees the output files may still know that encrypted data exists and may estimate the total amount of protected data unless padding is used. If you lose the passphrase or keyfiles, the data cannot be recovered.

---

## Appendix C: Maintainer Notes

This document should be updated whenever the project changes its cryptographic suite, KDF policy, metadata policy, padding behavior, restore safety model, or supported threat model. Security documentation should be versioned together with the software so that users can understand which claims apply to which release.
