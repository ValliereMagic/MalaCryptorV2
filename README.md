# MalaCryptor
## A tool for encrypting files using Quantum cryptography, Classical cryptography; or both.
___
## Running
```
git clone https://github.com/ValliereMagic/MalaCryptorV2.git
cd MalaCryptorV2/mala_cryptor
cargo build --release
cargo run --release -- [OPTIONS]
*or*
cd target/release
./mala_cryptor [OPTIONS]
```
___
## Output Example
```
mala_cryptor 2.0.0
ValliereMagic
A command line file cryptography tool

USAGE:
    mala_cryptor [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    pub     Public-Private key file encryption
    sym     symmetric file encryption with a key_file or password
```
___
## Usage
### Key Generation
#### Symmetric Keys
```
username@host:~$ mala_cryptor sym gen
mala_cryptor-sym-gen 
Generate a symmetric keyfile

USAGE:
    mala_cryptor sym gen [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --out_file <FILENAME>    specify an output filename
```

`mala_cryptor sym gen -o key_file_name_f`

#### Public - Private Keypairs
```
username@host:~$ mala_cryptor pub gen
mala_cryptor-pub-gen 
Generate a public-private keypair

USAGE:
    mala_cryptor pub gen [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -m, --mode <'q', 'c', 'h'>            specify type of keypair to generate: q: quantum, c: classical, h: hybrid
                                          (both, in cascade)
    -p, --public_key <Output FILENAME>    specify the output public key filename
    -s, --secret_key <Output FILENAME>    specify the output secret key filename

```

`mala_cryptor pub gen -m h -p hybrid_public_key_f -s hybrid_secret_key_f`\
`mala_cryptor pub gen -m q -p quantum_public_key_f -s quantum_secret_key_f`\
`mala_cryptor pub gen -m c -p classical_public_key_f -s classical_secret_key_f`

### Encryption of files
#### Symmetric
```
username@host:~$ mala_cryptor sym enc
mala_cryptor-sym-enc 
encrypt a file

USAGE:
    mala_cryptor sym enc [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --in_file <FILENAME>     specify a file to encrypt
    -k, --key_file <FILENAME>    specify a key file to use (if not specified, you will be prompted for a password)
    -o, --out_file <FILENAME>    specify an output filename
```

##### With Key File
`mala_cryptor sym enc -i file_to_encrypt -k key_file -o encrypted_filename`
##### With password (you will be prompted)
`mala_cryptor sym enc -i file_to_encrypt -o encrypted_filename`

#### Asymmetric
```
username@host:~$ mala_cryptor pub enc
mala_cryptor-pub-enc 
Encrypt a file using a public key [and sign]

USAGE:
    mala_cryptor pub enc [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --destination <Input FILENAME>    specify the public key of the recipient
    -i, --in_file <FILENAME>              specify a file to encrypt
    -m, --mode <'q', 'c', 'h'>            specify type of keypair to generate: q: quantum, c: classical, h: hybrid
                                          (both, in cascade)
    -o, --out_file <FILENAME>             specify an output filename
    -p, --public_key <Input FILENAME>     specify our public key for key exchange
    -s, --secret_key <Input FILENAME>     specify the secret key to sign with
```

undocumented!();

___