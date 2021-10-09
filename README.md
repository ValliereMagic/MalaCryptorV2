# MalaCryptor's Rebirth
## Running
```
git clone https://github.com/ValliereMagic/MalaCryptorV2.git
cd MalaCryptorV2
git submodule update --init --recursive
cd mala_cryptor
cargo build --release
cargo run --release -- [OPTIONS]
*or*
cd target/release
./mala_cryptor [OPTIONS]
```
## Output Example
```
mala_cryptor 0.2.0
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
