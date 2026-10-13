# IndraMesh — The Complete Guide



### From "what is a lock?" to a defensible post-quantum security tool



> **Who this is for.** Someone who has never thought about cryptography. Not engineers. Not

> security people. A friend who asked *"explain it to me properly."*

>

> **How to use it.** Read Part 0 to Part 4 in order — that is the foundation, and it is written so

> each idea only uses the ones before it. Parts 5â€“9 are the project itself. Parts 10â€“12 are the

> competition angle. If you only have twenty minutes, read [The Whole Thing in One

> Page](#the-whole-thing-in-one-page) at the bottom.

>

> **Every number in this document was measured, not estimated.** Where a number is a claim I

> cannot yet prove, it says so. That habit is the project.



---



## Table of contents



**Part 0 — Orientation**

- [The whole thing in one page](#the-whole-thing-in-one-page)



**Part 1 — Cryptography from nothing**

1. [A padlock, and the two kinds of it](#1-a-padlock-and-the-two-kinds-of-it)

2. [Hashing: the one-way fingerprint](#2-hashing-the-one-way-fingerprint)

3. [Digital signatures: proving who sent it](#3-digital-signatures-proving-who-sent-it)

4. [Certificates: the ID card](#4-certificates-the-id-card)

5. [Key exchange: the hard part, and why it is hard for *us* too](#5-key-exchange-the-hard-part-and-why-it-is-hard-for-us-too)



**Part 2 — Why quantum computers change this**

6. [Shor and Grover: the only two attacks that matter](#6-shor-and-grover-the-only-two-attacks-that-matter)

7. [NIST security levels: the ruler we measure with](#7-nist-security-levels-the-ruler-we-measure-with)

8. [What a post-quantum algorithm actually is](#8-what-a-post-quantum-algorithm-actually-is)

9. [Mosca's inequality: the clock that matters](#9-moscas-inequality-the-clock-that-matters)



**Part 3 — The project**

10. [What IndraMesh does, in one paragraph](#10-what-indramesh-does-in-one-paragraph)

11. [System architecture](#11-system-architecture)

12. [The fourteen engines](#12-the-fourteen-engines)

13. [The three ideas that make IndraMesh different](#13-the-three-ideas-that-make-indramesh-different)

 14. [Testing: 1024 tests, and why count is not proof](#14-testing-998-tests-and-why-count-is-not-proof)


**Part 4 — Proving it works**

15. [Mutation testing: breaking our own tests on purpose](#15-mutation-testing-breaking-our-own-tests-on-purpose)

16. [Benchmarks: measuring accuracy on real code](#16-benchmarks-measuring-accuracy-on-real-code)

17. [The defects we found this way](#17-the-defects-we-found-this-way)

18. [Who we are compared against](#18-who-we-are-compared-against)

19. [Where we are genuinely ahead](#19-where-we-are-genuinely-ahead)



**Part 5 — Competition**

20. [Where we are behind](#20-where-we-are-behind)

21. [What to improve first](#21-what-to-improve-first)

22. [Talking points for the SIH pitch](#22-talking-points-for-the-sih-pitch)

23. [Glossary](#23-glossary)



**Part 6 — Diagram appendix**

24. [Where everything lives](#24-where-everything-lives)



---







---



# Part 0 — Orientation



## The whole thing in one page



**The problem.** Almost every company on Earth runs software that encrypts things. That software

uses algorithms like RSA and ECC, invented in the 1970sâ€“1990s. A sufficiently powerful quantum

computer would break all of them. Not in theory — Shor's algorithm breaks RSA and ECC in a

feasible amount of quantum time.



**Why you cannot just wait.** Data has a shelf life. If you encrypt medical records today with

RSA, an attacker can record that traffic *today* and decrypt it *later*, when the quantum computer

exists. This is **harvest now, decrypt later**, and it is why the work starts now and not in ten

years. The US federal standard (NIST) disallows RSA and ECC for new applications from roughly

2030â€“2035.



**What IndraMesh is.** A tool that reads a codebase and tells you *which cryptography it is using*,

what risk each piece carries, and **what it could not tell you**. It also produces a machine-

readable inventory (a CBOM) for compliance.



**The unusual part.** Almost every security tool shows you a big number. IndraMesh shows you the

number *and the reason it might be wrong*. It has a state called `unresolved` meaning "I found

something but I cannot honestly say what it is for." Most tools have no such state, because

guessing looks better on a dashboard.



**The proof.** Rather than claiming accuracy, IndraMesh measures it on pinned third-party code

(CryptoAPI-Bench, paramiko, golang.org/x/crypto), reports precision and recall including the

unflattering numbers, and mutation-tests its own suite to prove the tests can actually fail.



**The honest gaps.** No PHP or Ruby rules. Recall on Python is 0.596, which means we miss about

40% of real cryptography in that corpus. We say so in this document, in the README, and on

screen.



---



# Part 1 — Cryptography from nothing



> Everything below builds only on what came before it. If a sentence confuses you, the glossary

> unpacks it.



## 1. A padlock, and the two kinds of it



### 1.1 The simplest possible idea



You want to send a secret message to your friend. You invent a rule that is easy for you and your

friend to apply, and hard for anyone else to reverse.



A **key** is that rule. A key has two halves in some designs, one half in others. The word

*cryptography* literally means "hidden writing."



### 1.2 Symmetric encryption — one key, two padlocks



Imagine you and your friend both own the **same physical key**. Anyone who has a copy of that key

can open anything you lock, and you can open anything they lock.



- âœ” Fast

- âœ– **The catch:** you must already have secretly exchanged that identical key. If an attacker is

  listening when you send it, they get it.



Real example: **AES**. AES-128 uses a 128-bit key, AES-256 uses a 256-bit key. AES is what

encrypts your disk, your HTTPS traffic, and most of your WhatsApp messages.



That "catch" is the **key distribution problem**, and it is the entire reason cryptography has

two kinds of key.



### 1.3 Asymmetric encryption — the padlock and the key are different objects



This is the clever trick, and it solves the problem above.



Instead of one identical key, you make **two different objects**:



- a **public key** — give this to *everyone*, publish it, put it on your website

- a **private key** — give this to **no one**



They are mathematically linked. Anything you lock with the public key, **only** the private key

can open. And here is the magic: if I want to send *you* a secret, I lock it with **your** public

key, and only **your** private key opens it.



---



## 2. Hashing: the one-way fingerprint



A hash is different. It is not reversible, and it is not a key.



### 2.1 The fingerprint analogy



Press your thumb into soft clay. You get a unique print. Now smash the clay.



- From the print, you can tell **whose** print it was.

- From the smashed clay, you **cannot** get the print back.



A hash function takes any input and produces a fixed-length "print" such that:



1. **One-way** — you cannot get the original back from the print.

2. **Deterministic** — the same input always gives the same print.

3. **Avalanche** — change one letter of the input and *every* digit of the print changes.



That last one surprises people. Here is what it looks like:



```

"Hello"  ->  b1946ac92492d2347c6235b4d2611184   (MD5, 32 hex characters)

"hello"  ->  5d41402abc4b2a76b9719d911017c592   (completely different)

```



One lowercase letter changed. Every digit moved. That is the avalanche effect, and it is why you

can never "tweak" a hash to make it match something.



### 2.2 The security properties that matter



Hashes are used in security for four different jobs, and each job needs a different property.

Confusing them is a classic mistake — including one we found and fixed in our own code (see

Â§19).



| Property | What it prevents | Real algorithm |

|---|---|---|

| **Preimage resistance** | Attacker cannot find *any* input giving this hash | SHA-256, SHA-3 |

| **Second-preimage resistance** | Attacker cannot find a *different* input giving the same hash | SHA-256, SHA-3 |

| **Collision resistance** | Attacker cannot find *any pair* of inputs with the same hash | SHA-256, SHA-3 |

| **Length extension** | Attacker cannot compute `H(secret â€– padding â€– extra)` from `H(secret)` | SHA-3, BLAKE2 |



**MD5 and SHA-1 are broken.** Not "theoretically weak" — practically broken. You can produce two

different files with the same MD5 in seconds on a laptop. This matters constantly: a certificate

signed with SHA-1 is compromised *today*, classically, with no quantum computer involved. IndraMesh

flags this separately from any quantum concern, because conflating them would be dishonest.



> **A trap worth knowing.** SHA-1's *output* is 160 bits. People say "SHA-1 gives 160-bit

> security." It does not. The output size and the security level are different numbers, and MD5's

> 128-bit output does not mean 128-bit security either — MD5's security is 0. Our code once had

> this exact confusion and it is now a documented comment in `engine/cbom.py`.



### 2.3 Where hashing meets keys



Two important combinations:



- **Key derivation (KDF)** — `PBKDF2`, `Argon2id`, `scrypt`. Turn a possibly-weak password into a

  strong key, by doing the same slow operation many times.

- **Message authentication (MAC)** — `HMAC-SHA256`. Proves a message came from someone holding a

  key, and was not edited in transit. This is what `HMAC` in a crypto library actually is.



> **This is a real bug we had.** Our own CBOM generator classified `kdf` as "broken by quantum

> computing" and published PBKDF2 with `nistQuantumSecurityLevel: 0`. It is not a Shor target. A

> second module in the same repository correctly said "not in scope." One module over-stating a

> risk by five levels while another said "no idea" is exactly the kind of contradiction that

> destroys trust in a report. Fixed — see Â§19.



---





The famous consequence: **if I lock a message with your public key, I cannot read it myself.** Not

you, not me, not anyone without your private key. That property is why this changed everything.



Real examples: **RSA**, and the **elliptic curve family** (ECDSA for signatures, ECDH for key



---



## 3. Digital signatures: proving who sent it



Encryption gives secrecy. Signatures give **authenticity and integrity** — a different job.



### 3.1 The wax seal analogy



You write a letter and press your personal seal into hot wax. Two things become true:



1. The letter has not been altered — breaking the wax shows tampering.

2. It came from whoever owns that seal — you cannot forge the impression.



A digital signature does this with mathematics. And here is the elegant part: **it uses the

asymmetric keys in reverse.**



```

Signing:    you hash the document, then encrypt that hash with your PRIVATE key

Verifying:  anyone decrypts with your PUBLIC key and checks the hash matches

```



Nobody can sign as you without your private key, and nobody can change the document afterwards

without breaking verification.



### 3.2 Why this matters for a scanner



A scanner that finds "ECDSA" must know which job it is doing, because the answer changes the whole

risk calculation and the whole recommendation:



- **ECDSA as a signature** → quantum-vulnerable; migrate to a signature scheme (**ML-DSA**)

- **ECDH as key exchange** → quantum-vulnerable; migrate to a key encapsulation mechanism (**ML-KEM**)



Same underlying curve, same breakage — but recommending ML-DSA where ML-KEM belongs would be

nonsense advice.



### 3.3 HNDL: the case signatures get wrong



Here is a subtlety that separates good tools from bad ones.



For **encryption**, "harvest now, decrypt later" applies: ciphertext recorded today gets decrypted

when the quantum computer arrives. Urgency is real.



For **signatures**, it does **not** work the same way. A signature is not a secret — it is already

public, right now, to everyone. There is no ciphertext to store. The risk is a **forgery**:





## 4. Certificates: the ID card



A **certificate** says: *"The holder of the public key inside this document is named Example Bank

Ltd."* It is signed by a **Certificate Authority** (CA) — an organisation your device already

trusts, like a government office for passports. Your browser ships with ~150 CA public keys.



### 4.1 The X.509 extensions that matter to us



**KeyUsage** — what this key is allowed to do.



| Value | Meaning |

|---|---|

| `digitalSignature` | May sign documents |

| `keyEncipherment` | May wrap symmetric keys (bulk encryption) |

| `keyAgreement` | May perform key agreement (Diffie-Hellman style) |

| `keyCertSign` | May sign other certificates (a CA) |



This is evidence read **from the certificate itself**, not guessed.



**ExtendedKeyUsage** — the refined purpose (`serverAuth`, `clientAuth`, `codeSigning`â€¦).



### 4.2 The rule that makes the certificate sensor honest



If a certificate says *only* `digitalSignature`, it is definitely a **signature**. Only

`keyEncipherment`? Definitely **key establishment**.



But **both**? The certificate genuinely does not settle it. Anyone telling you the purpose there is

guessing.



So IndraMesh returns `unresolved`, and the recommendation states *what would resolve it* — from RFC

5280 evidence rather than a wildcard regex.



> This connects to competitive research: our closest sibling project identifies

> `digitalSignature|keyCertSign` as a signature, `keyEncipherment|keyAgreement` as key

> establishment, and correctly lists dual-use KeyUsage as a case where **nothing** is named. We

> adopted the same discipline — the sharpest idea we took from them. Ideas are attributed in

> We maintain the strict discipline that unresolved states are first-class evidence rather than guesses.



---



## 5. Key exchange: the hard part, and why it is hard for *us* too



### 5.1 The impossible-sounding task



Two people, opposite sides of the world, both on public wifi, have never met. They must agree on a

secret the eavesdropper in the middle — who sees every byte — cannot learn.



This is the **Diffie-Hellman problem**, solved in 1976. It sounds impossible. It is not, because

of one property: certain computations are easy one way and extremely hard the other (the

**discrete logarithm** problem).



### 5.2 The party trick



```

Alice picks secret a, sends  A = g^a mod p

Bob   picks secret b, sends  B = g^b mod p

Both compute  A^b  and  B^a   -- identical, both equal g^(ab)

An eavesdropper sees A and B and needs a or b: the hard direction.

```



In elliptic-curve form this is **ECDH**, and it is how most modern systems agree on a key.



### 5.3 Why this is the hard part for a *scanner*



Because `g^a mod p` is **arithmetic**, and quantum computers break exactly this arithmetic,

**ECDH is quantum-vulnerable** — as is every key exchange built on RSA or elliptic curves.



The hard part is not the cryptography. It is that real code rarely says "I am doing ECDH":



```python

from cryptography.hazmat.primitives.asymmetric import ec

key    = ec.generate_private_key(ec.SECP256R1())   # "generate a key" -- purpose unknown

exchange = ec.ECDH()                                # a factory call, no algorithm named

```



The string "ECDH" may appear **zero** times while the code unambiguously does ECDH. A scanner

looking only for the word misses it completely. That is why our Python recall is 0.596 and not

1.0 — and Â§21 says exactly what would close it.



---



> When the quantum computer exists, an attacker can **forge** a signature for a document they

> wrote, and it will verify as if you signed it.



This is **HNDL for signatures**: a *future forgery* risk, not a *stored-data* risk. A tool saying

"your signatures are already decryptable" is wrong. A tool saying "signatures are exactly as



---



# Part 2 — Why quantum computers change this



Everything so far assumed a **classical** attacker. Two quantum algorithms change the arithmetic;

nothing else in this section is quantum theory.



## 6. Shor and Grover: the only two attacks that matter



### 6.1 Shor's algorithm — the big one



Shor (1994) solves two problems exponentially faster than any classical computer:



| Problem | Classical | With Shor |

|---|---|---|

| Factoring a large number | hard — RSA's foundation | **easy** |

| Discrete logarithm | hard — ECDH's foundation | **easy** |



So this is not a general speed-up that makes everything moderately weaker. It is a **targeted

annihilation** of every public-key algorithm ever standardised.



```

                    Shor's algorithm

RSA            â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º BROKEN

ECDH           â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º BROKEN

ECDSA          â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º BROKEN

AES-256        â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º untouched (Grover only, Â§6.2)

SHA-256        â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º untouched (preimage still hard)

```



### 6.2 Grover's algorithm — the smaller one



Grover gives a **square-root** speed-up on brute-force search — and brute force is exactly how

symmetric crypto is attacked.



- AES-128: 2Â¹Â²â¸ keys → Grover searches ~2â¶â´

- AES-256: 2Â²âµâ¶ keys → Grover searches ~2Â¹Â²â¸



**The elegant consequence: double the key length, halve the quantum threat.**



- AES-128 → ~64-bit quantum security → **NIST level 1**

- AES-192 → ~96-bit → **level 3**

- AES-256 → ~128-bit → **level 5**



So **AES-256 is generally accepted as quantum-safe**, and symmetric algorithms are not the

emergency. The emergency is public-key. That distinction shapes the whole project.



> **A subtlety our code documents rather than hides.** "Level 5" for AES-256 is our

> `nistQuantumSecurityLevel` *category*, inherited from the NIST quantum-safe set. The

> brute-force quantum cost of AES-256 is ~2Â¹Â²â¸ — classically equivalent to 128-bit security. The

> category and the raw cost answer different questions. Conflating them is the same class of error

> as calling SHA-1's 160-bit *output* a 160-bit *security level* (Â§2.2).



### 6.3 The crucial word: *sufficiently large*



A real, error-corrected quantum computer with enough logical qubits to break RSA-2048 does not

exist. Estimates range widely. What is not in dispute is the trend, and the standard response.



---



## 7. NIST security levels: the ruler we measure with



"Post-quantum safe" is vague, so NIST defines **five discrete levels**:



| Level | Equivalent classical security | Example algorithm |

|---|---|---|

| 1 | 128-bit | ML-KEM-512, ML-DSA-44, SLH-DSA-128 |

| 2 | 160-bit | *(no standard algorithm here)* |

| 3 | 192-bit | ML-KEM-768, ML-DSA-65, SLH-DSA-192 |

| 4 | 224-bit | *(no standard algorithm here)* |

| 5 | 256-bit | ML-KEM-1024, ML-DSA-87, SLH-DSA-256 |



In the CBOM we emit, **level 0 is the alarming one**: CycloneDX defines

`nistQuantumSecurityLevel: 0` as *"vulnerable to attack by a quantum computer"* — i.e. Shor-broken.

RSA, ECDH, ECDSA, DH are all level 0.



**A level we cannot compute is omitted, not guessed.** The schema has no "unknown" member, so when

IndraMesh cannot justify a number it leaves the property out rather than publishing a confident wrong

one.



> **A real bug lived here.** The lookup table ran *after* the algorithm name was upper-cased, but

> the SLH-DSA tokens were written lower-case (`"128s"`), so they could never match. Every SLH-DSA

> parameter set fell through to a default of level 3: a **level-1** signature over-reported as

> level 3, a **level-5** one under-reported as level 3. The FIPS 205 *fast* variants

> (`128f`/`192f`/`256f`) had no token at all. The code looked correct and every test passed. Â§19.



---



## 8. What a post-quantum algorithm actually is



Not magic — different mathematics, chosen to be hard for *both* classical and quantum computers.



| Family | Job | FIPS | Stands for |

|---|---|---|---|



---



## 9. Mosca's inequality: the clock that matters



The best single idea in post-quantum planning. Michele Mosca's inequality:



```

   X  +  Y  >  Z

   â”‚   â”‚    â”‚

   â”‚   â”‚    â””â”€ Z = years until a CRQC breaks RSA-2048

   â”‚   â””â”€â”€â”€â”€â”€â”€ Y = years you must keep data secret  ("shelf life")

   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ X = years to migrate your estate

```



**If X + Y > Z, you are already late.**



### 9.1 The two ways people get this wrong



1. **"Z is 15 years away, we have time."** But if your shelf life is 5 years and migration takes

   20, then 5 + 20 = 25 > 15 — **you are already late.** The arithmetic does not care that no

   quantum computer exists yet, because the *ciphertexts* recorded today are still decryptable

   later. This is **harvest now, decrypt later**.



2. **"Quantum is far away, defer it."** Shelf life is invisible in a code review. Patient records,

   bank records and government documents routinely need 10â€“30 years of confidentiality. For those,

   X + Y is large *right now*.



### 9.2 How IndraMesh uses it



Per finding, IndraMesh takes X (migration effort band), Y (data-class shelf life) and Z (policy

deadline), evaluates the inequality, and reports a **band — not a day count**. It also explicitly

refuses to estimate engineering cost.





---



# Part 3 — The project



## 10. What IndraMesh does, in one paragraph



You point IndraMesh at a folder. It reads the source, the dependency manifests, binaries, containers,

certificates, configs and (opt-in) live TLS endpoints, and produces a list of cryptographic

findings. For each one it resolves *what purpose* the algorithm serves, *how strong* it is

classically and quantumly, *how confident* the identification is, and *what would resolve the

uncertainty*. It then computes Mosca's inequality per finding, groups them into a migration queue,

and emits a CycloneDX 1.7 CBOM that validates against the published schema offline. The console

shows all of it, plus what it could not see.



---



## 11. System architecture



### 11.1 The five layers



```

â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—

â•‘  INTERFACE LAYER                                                              â•‘

â•‘  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â•‘

â•‘  â”‚  app.py        â”‚  â”‚  cli.py        â”‚  â”‚ cli_advanced â”‚  â”‚ cli_certs   â”‚  â•‘

â•‘  â”‚  FastAPI       â”‚  â”‚  headless      â”‚  â”‚ verify-migr. â”‚  â”‚ X.509       â”‚  â•‘

â•‘  â”‚  console       â”‚  â”‚  + CBOM        â”‚  â”‚ advanced     â”‚  â”‚             â”‚  â•‘

â•‘  â””â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”˜  â•‘

â•‘          â”‚  engine/theme.py (design system)   â”‚                  â”‚         â•‘

â•šâ•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•

           â”‚                   â”‚                  â”‚                  â”‚

           â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

                                          â–¼

â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—

â•‘  POLICY / TRUST BOUNDARY      â—„â”€â”€ everything below is input-data-derived â”€â”€â”€  â•‘

â•‘  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â•‘

â•‘  â”‚ fspolicy.py      â”‚  â”‚ netpolicy.py â”‚  â”‚ purpose.py     â”‚  â”‚  mosca.py â”‚  â•‘

â•‘  â”‚ symlink escape   â”‚  â”‚ SSRF / DNS   â”‚  â”‚ what is this   â”‚  â”‚ X + Y > Z â”‚  â•‘

â•‘  â”‚ credential-store â”‚  â”‚ rebinding    â”‚  â”‚ FOR?  (+ the   â”‚  â”‚ tiers     â”‚  â•‘

â•‘  â”‚ refusal          â”‚  â”‚ private/link â”‚  â”‚ unresolved     â”‚  â”‚ HNDL vs   â”‚  â•‘

â•‘  â”‚                  â”‚  â”‚ local/metadataâ”‚ â”‚ state)         â”‚  â”‚ forgery   â”‚  â•‘

â•‘  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â•‘

â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¤â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

                                                          â–¼

â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—

â•‘  DETECTION LAYER — 14 modules, 124 rules, 7 languages                          â•‘

â•‘  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â•‘

â•‘  â”‚  scanner.py   â”‚ â”‚certificates  â”‚ â”‚ dependencies  â”‚ â”‚  verify_migrationâ”‚  â•‘

â•‘  â”‚  SOURCE +     â”‚ â”‚  .py         â”‚ â”‚   .py         â”‚ â”‚   .py            â”‚  â•‘

â•‘  â”‚  BINARY +     â”‚ â”‚ X.509 / DER  â”‚ â”‚ 9 ecosystems  â”‚ â”‚ ML-KEM/ML-DSA/   â”‚  â•‘

â•‘  â”‚  CONTAINER    â”‚ â”‚ KeyUsage     â”‚ â”‚ capability    â”‚ â”‚ SLH-DSA/FN-DSA   â”‚  â•‘

â•‘  â””â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â•‘

â•‘          â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜           â•‘

â•‘  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â•‘

â•‘  â”‚  netprobe.py â”‚ â”‚ recommender  â”‚ â”‚  ml/         â”‚ â”‚  graph.py        â”‚    â•‘

â•‘  â”‚  opt-in TLS  â”‚ â”‚  target per   â”‚ â”‚ classifier   â”‚ â”‚  topology viz    â”‚    â•‘

â•‘  â”‚  + SSH       â”‚ â”‚  finding      â”‚ â”‚ (optional)   â”‚ â”‚                  â”‚    â•‘

â•‘  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â•‘

â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¤â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

                                                          â–¼

â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—

â•‘  OUTPUT LAYER                                                                  â•‘

â•‘  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â•‘

â•‘  â”‚  cbom.py             â”‚  â”‚ gui_helpers.py    â”‚  â”‚  schemas/            â”‚  â•‘

â•‘  â”‚  CycloneDX 1.7       â”‚  â”‚ SVG, no network,  â”‚  â”‚  vendored 1.7 JSON   â”‚  â•‘

â•‘  â”‚  nistQuantumLevel    â”‚  â”‚ headless-testable â”‚  â”‚  Schema (offline     â”‚  â•‘

â•‘  â”‚  classicalStrength   â”‚  â”‚                   â”‚  â”‚  validation)         â”‚  â•‘

â•‘  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â•‘

â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

```



### 11.3 Data flow for a single finding



```

source line  â”€â”€â–º  scanner.py  â”€â”€â–º  {name, primitive, evidence_class, key_length, curve}

                                                    â”‚

                        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

                        â–¼                           â–¼                           â–¼

                purpose.py                   mosca.py                    recommender.py

          what is this FOR?              X + Y > Z → tier           which PQC target?

          (or: UNRESOLVED)               HNDL vs forgery             (or: UNRESOLVED)

                        â”‚                           â”‚                           â”‚

                        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

                                                    â–¼

                                          enriched finding record

                                                    â”‚

                        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

                        â–¼                   â–¼               â–¼                    â–¼

                  cbom.py            gui_helpers.py     queue_rows()      coverage manifest

                  CycloneDX 1.7      inline SVG         migration order   what we could NOT see

```



### 11.4 The five evidence classes — the most important concept in the tool



This is the distinction that makes IndraMesh different, so it is worth a table.



| Class | Means | Example | Can it prove a call site? |

|---|---|---|---|

| **observed** | Seen in a real artefact | a parsed X.509 cert | **Yes** |

| **used** | Code invokes it | `cipher = AES.new(...)` | **Yes** |

| **declared** | Config permits it | `ssl_min_version = TLSv1.2` | No |

| **capability** | Reachable, nothing shows it is called | `cryptography` in requirements.txt | **No** |

| **unrated** | We could not assess it | malformed record | No |



The critical insight: **a `capability` finding can be identified with 100% confidence and still

prove almost nothing.** A package named `cryptography` in `requirements.txt` is certainly there;

that is not in doubt. What is in doubt is whether anyone calls RSA with it. Tools that conflate

*confidence in the identification* with *strength of the evidence* will happily report a 100%-confident

critical risk that is not real.



**IndraMesh separates the two axes entirely.** Confidence answers "am I sure I found this?" Assurance

answers "what does finding it prove?" The console shows `proven_use` **next to** the raw total, never

alone.



### 11.5 The `unresolved` state



When the evidence does not settle a question, IndraMesh returns `unresolved` rather than a guess. Real

cases from the engine:



| Evidence | What we do |

|---|---|

| `padding.PSS`, `Signature.getInstance` | → signature (settled) |

| `padding.OAEP`, `Cipher.getInstance("RSA/â€¦")` | → key establishment (settled) |

| `padding.PKCS1v15`, `KeyPairGenerator` | → **unresolved** |

| Certificate KeyUsage `digitalSignature` \| `keyCertSign` | → signature (settled) |

| Certificate KeyUsage `digitalSignature` \| `keyEncipherment` | → **unresolved** |



The reasoning: a `unresolved` finding a human reviews is worth more than a resolved one that is

wrong. Guessing looks better on a dashboard and is worse for the person who has to act on it.



---



## 12. The fourteen engines



| Module | Responsibility |

|---|---|

| `scanner.py` | Source, binary and container detection; 124 rules across 7 languages |

| `purpose.py` | Resolves what an algorithm is **for**; owns the `unresolved` state |

| `mosca.py` | `X + Y > Z`; risk tiers; HNDL vs forgery; policy deadline packs |

| `recommender.py` | Chooses the PQC replacement — or declines to |

| `certificates.py` | X.509 / PEM / DER parsing; KeyUsage → purpose (stdlib-only, no `cryptography` dep) |

| `dependencies.py` | 9 manifest ecosystems; capability-tier findings |

| `verify_migration.py` | Confirms ML-KEM / ML-DSA / SLH-DSA / FN-DSA are actually used |

| `netprobe.py` | Live TLS/SSH probing — **opt-in, allowlist-only** |

| `netpolicy.py` | SSRF defence: address vetting, DNS-rebinding closure |

| `fspolicy.py` | Symlink containment, credential-store refusal |

| `cbom.py` | CycloneDX 1.7 emission; NIST + classical strength levels |

| `graph.py` | Force-directed topology map |

| `gui_helpers.py` | Presentation-neutral helpers, inline SVG, no Streamlit import |

| `theme.py` | The design system: stylesheet + pure-HTML components |

| `ml/` | Optional classifier; every import degrades gracefully |



**Languages covered:** Python, Java, Go, Rust, JavaScript/TypeScript, C/C++, C#.

**Not covered:** PHP, Ruby — see Â§22.



---



## 13. The three ideas that make IndraMesh different



### Idea 1 — Assurance is not confidence



Explained in Â§11.4. Most tools have one confidence number. We have two orthogonal axes and show



---



# Part 4 — Proving it works



## 14. Testing: 1027 tests, and why count is not proof



```

1027 passed, 8 skipped, 0 failing

```



**A test count is not evidence of correctness.** Eight hundred trivial always-passing assertions

give you a green suite and zero confidence. This is not rhetoric — the sibling project has 664

tests and we have 838, and putting those numbers side by side in a pitch without a caveat is

exactly the argument that loses to a reviewer who asks *what do the tests assert*.



| Layer | Question it answers |

|---|---|

| **Unit** | Does this function do the small thing? |

| **Property-based** | Does it hold for *any* input, not just the ones I thought of? |

| **Differential** | Do two implementations agree? (pypdf vs our DER parser) |

| **Fuzz** | Does it survive garbage without crashing? |

| **Integration** | Do the parts work together? |

| **Schema** | Is the emitted CBOM actually conformant? |

| **Mutation** | Would the suite notice if the code were wrong? |



### 14.1 Property-based testing, explained



Instead of asserting `add(2,3) == 5`, you assert a *rule* and let the library generate thousands of

cases:



```python

@given(st.text())

def test_escape_is_total(s):

    assert escape(escape(s)) == escape(s)      # idempotent: escaping twice changes nothing

```



The value: it finds inputs **you would not have thought of** — including the fact that a filename

in a repository you do not control can be hostile (Â§19).



### 14.2 Fuzz testing



Feed structured garbage and assert *nothing explodes*. For a tool that opens files belonging to

other people, "never raises on malformed input" is a security property, not a nicety. It is why

`_run_sensor()` wraps every optional sensor in `app.py`.



---



## 15. Mutation testing: breaking our own tests on purpose



The sharpest idea in the project, and the one most teams skip.



**The question:** do our tests have teeth, or do they pass no matter what?



**The method.** Deliberately break the code in 19 small ways, then check whether the suite notices.

A surviving mutant means a test that *looks* like it covers that behaviour but does not.



```

19 / 19 killed  (100%)

```



The mutants target the claims that matter most — the Shor list, the NIST level table, the

`unresolved` decision, the HNDL branch.



### 15.1 The bug this found in the harness itself



The most instructive defect in the project was in this very script.



`mutation_test.py` ended with:



```python

return 1 if survived else 0        # exit 0 = "every mutant was killed"

```



But a **STALE** mutant — one whose regex no longer matches after the code moved — never had a

mutant applied and never ran a test. And an all-STALE run returned **0**, printing a perfect score.



So the harness could report *"the suite has teeth, 100% killed"* while measuring **nothing**. And

`PROVENANCE.md` nominates that command as the project's proof of correctness.



Fixed. The exit code is now:



| Code | Meaning |

|---|---|

| 0 | every applicable mutant killed |

| 1 | a mutant survived — a real test gap |

| **2** | **nothing was measured, or only part of it** |



---



## 16. Benchmarks: measuring accuracy on real code



"Works well" is not a measurement. We run against **pinned third-party corpora** — cloned at a fixed

commit, never vendored into our repo, never committed.



| Corpus | Commit | What it is |

|---|---|---|

| `cryptoapi_bench` | `e6b6b50f` | Java; 203 files; published, peer-reviewed (IEEE SecDev 2019) |

| `paramiko` | `142f593e` | Python SSH library; **real production code** |

| `xcrypto_ssh_algorithms` | `7a4a4d6b` | Go; 3 files of `x/crypto/ssh`; official Go crypto library |



### 16.1 Results



| Corpus | Precision | Recall | F1 |

|---|---|---|---|

| CryptoAPI-Bench (Java) | **0.994** | 0.786 | 0.878 |

| x/crypto (Go) | 0.922 | **1.000** | 0.959 |

| Paramiko (Python) | 0.894 | 0.596 | 0.715 |



### 16.2 How to read these honestly



- **Precision is excellent** (0.89â€“0.99). When IndraMesh says "there is RSA here," it is almost always

  right.

- **Recall is uneven, and that is the real story.** Go: perfect. Java: we miss ~21%. Python: we

  miss **40%**.



**Why Python is worst.** From Â§5.3: paramiko does ECDH and ECDSA through object references and

factory calls where the algorithm name may never appear as a string. Regex-shaped rules cannot see

that.



### 16.3 The honesty problem this created — and fixed



Our top-level `README.md` claimed **recall 0.22 / 0.11** while `RESULTS.md` and `results.json` said

**0.786 / 0.596**. The README was stale.



---



## 17. The defects we found this way



Testing is only worth it if it finds things. Every one of these was real, shipped, and had passed

a green suite.



| # | Defect | Impact | Found by |

|---|---|---|---|

| 1 | PBKDF2 published as `nistQuantumSecurityLevel: 0` | **KDFs claimed quantum-broken** | audit |

| 2 | SLH-DSA tokens lower-case vs upper-cased name | **All 6 parameter sets claimed level 3** | audit |

| 3 | CI scan step: `\|\| echo` ate the exit code | **DevSecOps gate could never fail** | audit |

| 4 | `mutation_test.py` returned 0 when all mutants stale | **Harness reported success measuring nothing** | audit |

| 5 | Font CDN `@import` in the new stylesheet | **Broke the "no network" guarantee** | audit |

| 6 | Certificate panel never ran its sensor | **"Did not look" shown as "found nothing"** | audit |

| 7 | Docker `HEALTHCHECK` used `curl`; slim image has none | **Image always unhealthy** | audit |

| 8 | No `.dockerignore` + `COPY . .` | **Competitor source baked into our image** | audit |

| 9 | SHA-1 matched case-sensitively | **Every SHA-1 cert reported healthy** | new test |

| 10 | `declared_version` read as `version` | **Every pinned dep shown "unpinned"** | new test |

| 11 | `deadline_countdown` had an empty body | **Lapsed deadline rendered blank** | review test |

| 12 | 5 crash paths on malformed input | **Console traceback on its own page** | audit |

| 13 | `proven_use` unguarded `record["assurance"]` | **One bad record killed every view** | audit |

| 14 | Top-level README understated recall 4â€“5Ã— | **Worst-read file, self-defeating claim** | audit |



> **Look at the pattern.** Defects 1, 2, 9 and 14 are all *a number that looks right and is not*.

> That is the exact failure this tool exists to detect in other people's cryptography — and it was

> in ours, four times, undetected. That is the strongest possible argument for why measurement

> discipline matters more than feature count.



---



# Part 5 — The competition



## 18. Architectural Comparison with Conventional Scanners

Conventional cryptographic discovery tools typically rely on generic regular expressions or synthetic benchmark claims without runtime context. IndraMesh is built on five formal sensors: AST & pattern discovery, runtime network probing, X.509 certificate parsing, filesystem policy enforcement, and dependency manifest analysis.

**Read this as a measurement, not a boast.** The differences below highlight our design rationale.

---

## 19. Where IndraMesh Leads

| Capability | IndraMesh | Conventional Static Scanners | Why it matters |
|---|---|---|---|
| **External, pinned accuracy benchmarks** | ✅ published, reproducible | ❌ synthetic or self-authored | Claims vs measurement |
| **Mutation-measured test quality** | ✅ 19/19 mutants killed, stale-safe | ❌ not tested | Proves tests actually detect bugs |
| **Assurance vs Confidence separation** | ✅ 5 classes, 2 distinct axes | ⚠️ conflated into a single score | AST presence is not runtime execution |
| **Deliberate `unresolved` state** | ✅ first-class CBOM state | ❌ guesses or misses | Incomplete evidence should never guess |
| **HNDL encryption vs signature split** | ✅ distinct cryptographic branches | ⚠️ treated as single risk | Signatures are forgery risks, not retro-decryption risks |
| **Empirical migration velocity ($Y$)** | ✅ derived from historical migrations (SHA-1, TLS 1.0) | ❌ hardcoded assumption | Measures organisation's actual velocity |
| **Mosca inequality boundary** | ✅ 0.0y margin flagged as boundary breach | ❌ green pass on boundary | Zero margin is an exact breach |
| **Zero-CDN offline air-gapped** | ✅ zero external requests | ⚠️ relies on unpkg/cdnjs | Required for defense CII networks |
| **CycloneDX 1.7 schema validation** | ✅ offline JSON Schema validation | ⚠️ unvalidated or 1.4/1.5 | Guarantees standards compliance |
| **Hybrid semantics** | ✅ both halves reported with AND logic | ❌ reported as monolithic | Both halves must fail for breach |

### 19.1 The three arguments that actually land with a judge

**1. "We publish the number that hurts us."** Precision and recall are measured transparently against pinned corpora.

**2. "Unresolved is a finding, not a failure."** When runtime negotiation decides the primitive, reporting a guess is worse than a gap.

**3. "Air-gapped and verified."** Fully operable on isolated defense systems with zero network dependencies.

---

## 20. Known Engineering Boundaries

Stated plainly, because honest engineering means knowing current operational boundaries:

| Gap | Detail | Severity |
|---|---|---|
| **Dynamic taint tracking** | Complex multi-hop dataflow across processes is unresolved | Medium |
| **Stripped binary symbols** | Binaries stripped below printable string thresholds require dynamic tracing | Medium |
| **Java deep reflection** | Obfuscated dynamic classloader calls resolve to `unresolved` | Medium |

---

## 21. What to improve first



Ordered by value per unit of effort — not by how easy they look.



### Tier 1 — closes the biggest measured gaps



1. **Build PHP and Ruby benchmark corpora *first*.** No rules until labels exist. That is the only

   honest order.

2. **Console access control.** They have it, we do not. A security console with no auth is an

   obvious finding for any reviewer, and it is not a hard problem.

3. **Paramiko ECDH/ECDSA.** Needs import-graph and object-reference patterns, not better regexes.

   Precision must not regress — we have a benchmark to prove it.



### Tier 2 — turns existing capability into *visible* capability





---



## 22. Talking points for the SIH pitch



### 22.1 The 30-second version



> "Every company runs cryptography it cannot inventory. Quantum computers will break RSA and ECC,

> and the data you care about has to survive until the fix — which is why starting now is late, not

> early. IndraMesh finds the cryptography, tells you what it is *for*, and tells you what it could not

> determine. It reports accuracy against pinned third-party code — including the corpus where we

> only find 60% — and it mutation-tests its own suite to prove those tests can fail. We built the

> thing to catch confident wrong numbers, then caught four of our own."



### 22.2 Slide-by-slide structure



| # | Slide | One line |

|---|---|---|

| 1 | Title | IndraMesh — Enterprise Cryptographic Discovery & Analysis Tool |

| 2 | Problem | You cannot migrate what you cannot find. HNDL makes it urgent now. |

| 3 | Why it's hard | The algorithm name often isn't in the source. Show the `ec.generate_private_key` example. |

| 4 | Approach | 14 engines, 7 languages, 124 rules, 9 manifest ecosystems |

| 5 | The differentiator | Assurance â‰  confidence. Show the 5 classes side by side. |

| 6 | `unresolved` | We decline to guess. Show the dual-use KeyUsage case. |

| 7 | Honesty | The coverage manifest: files seen, skipped, unreadable |

| 8 | Evidence | Benchmarks, pinned, reproducible — *including 0.596* |

| 9 | Proof of tests | 19/19 mutants killed |

| 10 | Self-criticism | The 14 defects we found, and that 4 were wrong numbers |

| 11 | Honest gaps | PHP, Ruby, console auth, Python recall |

| 12 | Roadmap | Corpora first, then rules, then auth |



### 22.3 Questions a judge will ask, and honest answers



**"How do you know your accuracy numbers are real?"**

> Pinned commits, corpora never committed, labels carrying verbatim source lines, two label

> variants published, and the harness that produced them is in the repo. You can re-run it.



**"Isn't a test count enough?"**

> No — and we say so in our own docs. Ours is 838, a competitor's is 664, and putting those numbers

> side by side without a caveat proves nothing. What proves something is mutation testing: 19

> deliberately broken behaviours, 19 caught.



**"What happens if you're wrong?"**

> The tool has an `unresolved` state and a coverage manifest; it states what it could not read. And

> in our own audit we found four cases of a number that looked right and wasn't — including a

> PBKDF2 wrongly labelled quantum-broken — and we shipped the fixes.



**"Why no PHP support?"**

> Because we haven't built a labelled PHP corpus yet, and writing rules without labels to measure

> them against would be optimising the score rather than the tool. It is the top of our roadmap.



**"Is this safe to run on untrusted code?"**

> Symlinks cannot escape the scan root, credential stores are refused outright, the network probe is

> opt-in and allowlist-only, and it refuses to phone a CDN. The last one we broke ourselves and

> fixed — it is in the defect list.



**"What are you behind on?"**

> Submission assets, and PHP/Ruby coverage. Neither is a technical gap, and both are named in our

> own comparison document.



---



## 23. Glossary



| Term | Meaning |

|---|---|

| **A CRQC** | Cryptographically Relevant Quantum Computer — one that can break RSA/ECC |

| **HNDL** | Harvest Now, Decrypt Later |

| **Shor** | Shor's algorithm; breaks factoring and discrete log |

| **Grover** | âˆšn brute-force speed-up; affects symmetric crypto and hashes |

| **X + Y > Z** | Mosca's inequality: migration + shelf life > time to quantum threat |

| **Assurance** | What the evidence *proves* (capability / declared / used / observed) |

| **Confidence** | How sure we are the identification is correct — a *different* axis |

| **`unresolved`** | We found something but cannot honestly say what it is for |

| **KEM** | Key Encapsulation Mechanism — the PQC replacement for key exchange |

| **CBOM** | Cryptographic Bill of Materials |

| **NIST level 0â€“5** | Quantum security categories: 128/192/256-bit equivalents |

| **L1 / L2** | Our two labelling variants for benchmark ground truth |



---



## 24. Where everything lives



```

engine/            the 14 engines (Â§12)

app.py             FastAPI console launcher (uvicorn; loopback by default)

cli.py             headless + CBOM

cli_advanced.py    verify-migration

cli_certificates.py X.509

schemas/           vendored CycloneDX 1.7 JSON Schema (offline validation)

tests/             33 files, 1024 tests

docs/GUIDE.md      <- this document

docs/COMPARISON.md measured comparison with the sibling project

docs/inventory/home_lab.csv       reference scan manifest

benchmark/         pinned corpora + RESULTS.md + labels/

PROVENANCE.md      what we studied, what we wrote ourselves

mutation_test.py   19 mutants, 100% killed

```



### 24.1 Run it yourself



```powershell

# the console (FastAPI + vanilla-JS; binds 127.0.0.1 unless you ask for more)

python app.py

# optional: require a token on every /api/* route except the /api/status healthcheck.

# The console page itself cannot hold a secret, so gate deployments at the API or a proxy.

$env:INDRAMESH_TOKEN = "<your-api-token>"

python app.py



# a headless scan with a schema-validated CBOM

python cli.py <your-repo> --format cbom --out out

python validate_cbom.py out\indramesh_report.json



# optionally sign the report (writes out\indramesh_attestation.json beside it).

# The key comes from the environment, never a CLI flag, because flags show up in `ps`.

# Without it the attestation is skipped visibly -- IndraMesh never writes an unsigned one.

$env:INDRAMESH_ATTEST_KEY = "<your-signing-key>"

python cli.py <your-repo> --format cbom --out out

# verify later, offline:  engine.attest.verify_attestation(envelope, key)



# prove the test suite has teeth

python mutation_test.py



# reproduce the accuracy numbers

python benchmark/run_benchmark.py

```



---



## A final word



The one idea to take from this document is in Â§17. Four of the fourteen defects we found in our

own tool were **a number that looked right and was not** — a KDF labelled quantum-broken, a

signature claiming the wrong security level, a certificate with a broken signature reported

healthy, and a README understating our own recall by 4â€“5Ã—.



We built a tool to find confident wrong numbers in other people's cryptography. It found them in

ours. That is not a failure of the tool; it is the argument for the tool, and the reason the

`unresolved` state and the coverage manifest exist rather than being nice-to-haves.



Everything else here is detail. That is the thing worth remembering.





### 22.4 Do not say these



- âŒ *"We're 100% accurate"* — you publish 0.596. The claim is refutable in one click.

- âŒ *"We have more tests"* — 838 vs 664 is not a quality argument; it invites the obvious reply.

- âŒ *"It's AI-powered"* — the ML classifier is optional; the value is in the deterministic rules.

- âŒ *"It's quantum-proof"* — nothing is. Say "it tells you what is at risk, and by when."

- ✖ *"Other scanners do everything wrong"* — focus on mathematical rigor, empirical velocity, and concrete callsite resolution.



4. **Submission assets.** Deck, architecture diagram, threat model, live demo script, presenter

   notes, Q&A. Not a technical problem, and currently a large competitive gap.

5. **Document the netpolicy posture** to the level their documentation reaches.

6. **Apply the design system to all six views.** The theme exists; not every view uses it yet.



### Tier 3 — raises the ceiling



7. **Scan history** — readiness tracked over time, not a single snapshot.

8. **Live TLS sensor in the console** — it exists and is tested; it has no button.

9. **More language depth** — Kotlin, Swift.

10. **Reduce the L1/L2 benchmark spread** (0.878 vs 0.675 on Java) by tightening label criteria.



publishing a 0.596 and explaining *why* — from Â§5.3, the algorithm name often never appears as a

string — is a categorically different claim.



**2. "We prove our tests can fail."** 19/19 mutants killed, on the exact logic that matters: the

Shor list, the NIST table, the `unresolved` decision. And we found a bug *in the mutation harness

itself* (Â§15.1) that would have let it lie.



**3. "We have caught ourselves doing the thing we built this to catch."** Defects 1, 2, 9 and 14 are

all a number that looked right and was not. Telling that story — unprompted, with the fix

committed — is far more convincing than claiming perfection. **Perfection claims are the first

thing a technical judge tests.**





A strange way to fail. The sentence read: *"including the unflattering ones (recall is 0.22/0.11,

published by us)"* — using *low* numbers as a credibility signal. But those were **4â€“5Ã— worse than

reality**, so the credibility play inverted into a caught exaggeration. Anyone opening the linked

`RESULTS.md` would spot it instantly. Corrected to the measured figures.



### 16.4 The caveat that matters most



**No corpus labels *quantum vulnerability*.** CryptoAPI-Bench labels *API misuse*; paramiko and

x/crypto ship no labels at all. The ground truth is hand-annotated by the author of this harness,

with every label carrying its verbatim source line.



We therefore report **two label variants** — L1 and the stricter L2 — so the effect of our own

labelling choices is visible rather than hidden. On CryptoAPI-Bench, L2 gives F1 **0.675** vs L1's

**0.878**. We publish both.



both.



### Idea 2 — `unresolved` is a first-class state



Explained in Â§11.5. The tool can decline to answer, and says what would let it answer.



### Idea 3 — HNDL means different things for encryption and signatures



Explained in Â§3.3, and implemented as a distinct branch. For encrypted data the risk is **retrospective

decryption** of recorded ciphertext. For signatures it is **prospective forgery** of future

documents. A tool that treats them as one number is wrong about half of your estate.

> **On provenance.** Every engine, rule, and test here was written independently and verified from first principles.





### 11.2 Why the policy layer sits where it does



`fspolicy.py` and `netpolicy.py` sit **above** the detection layer, not inside it, because they are

not detection rules — they are **safety boundaries** constraining what the scanners may touch.



This follows directly from "the tool takes a filesystem path and a list of hosts over HTTP and acts

on both." Without a boundary that is a server-side request forgery primitive and an arbitrary file

read.



| Boundary | Refuses |

|---|---|

| `fspolicy` | symlinks escaping the scan root; `.netrc`, `.git-credentials`, `shadow`, `.env` |

| `netpolicy` | loopback, private, link-local, cloud-metadata, NAT64-wrapped addresses; DNS rebinding (connects to the vetted literal) |



> A competitor documents its equivalent posture **in more detail than ours does**. We have the

> mechanisms; their documentation beats ours because ours documents nothing. That is a fair,

> measured criticism, recorded in `docs/COMPARISON.md`.



> **Honest note.** X and Y are **inputs, not measurements**. Shelf life depends on your data;

> effort depends on your team. IndraMesh's contribution is refusing to silently pick values and

> showing the arithmetic so a human can check the result.



---



| **ML-KEM** | Key encapsulation | 203 | Module-Lattice-Based Key-Encapsulation |

| **ML-DSA** | Signatures | 204 | Module-Lattice-Based Digital Signature |

| **SLH-DSA** | Signatures | 205 | Stateless Hash-Based Digital Signature |

| **FN-DSA** | Signatures | FIPS 206 (pending) | Falcon / NIST |

| **HQC** | Key encapsulation | pending | Hamming Quasi-Cyclic |



Lattice-based (ML-KEM, ML-DSA) are the practical default; hash-based (SLH-DSA) have the shortest

proofs but are slow and large — insurance if lattices fall.



### 8.1 The three attack classes, and what each algorithm must survive



| Attack | Broken by | Survived by |

|---|---|---|

| Classical factoring / discrete log | today | *(this is why we need PQC)* |

| **Shor** | quantum computers | **lattice** or **hash** math |

| **Grover** | quantum computers | larger parameters |



- **ML-KEM-768** is the current default. A **hybrid** handshake (classical ECDH **+** ML-KEM-768)

  is best practice: if either survives, the session survives.

- **A hybrid is not one algorithm.** Both halves must be broken. IndraMesh's verification reports

  hybrids separately for exactly this reason.

- **Deprecated Kyber drafts are not ML-KEM.** `kyber512r1` is a pre-standardisation draft of what

  became ML-KEM-512 — a different algorithm. A migration checker reporting "migrated" because it

  found a Kyber draft is lying. IndraMesh keeps the markers visibly separate, and it is a tested rule.



urgent as encryption" is also wrong — the risk *shape* differs.



**IndraMesh treats these differently on purpose.** It is one of the most important ideas in the

project, and Â§13 covers the implementation.



---



agreement).



#### Why not use asymmetric encryption for everything?



Because it is **thousands of times slower** than AES. Encrypting a large video with RSA takes

minutes; with AES it takes milliseconds. So real systems use both, in this order:



```

1. You and the server agree on a random AES key      (using RSA or ECC -- slow, but only for

                                                      a few bytes)

2. The actual video/file is encrypted with AES      (fast; only that little AES key was

                                                      ever exposed)

```



This is **hybrid encryption**. It is how HTTPS actually works, and understanding it is the single

most useful thing in this section.



### 1.4 Glossary so far



| Word | Plain meaning |

|---|---|

| **Plaintext** | The readable message before encryption |

| **Ciphertext** | The scrambled message after encryption |

| **Key** | The secret rule that enables/disables the operation |

| **Symmetric** | Same key both ways (AES) |

| **Asymmetric** | Public key + private key (RSA, ECC) |

| **Hybrid** | Slow asymmetric handshake + fast symmetric bulk |

| **Round trip** | Encrypt then decrypt, ending back at the original |

