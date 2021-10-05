# MalaCryptor's Rebirth
## Running
```
git clone https://github.com/ValliereMagic/MalaCryptorV2.git
cd MalaCryptorV2
git submodule update --init --recursive
cd mala_cryptor
cargo build --release
cargo run
*or*
cd target/release
./mala_cryptor
```
## Output Example
```
mala_cryptor 0.1.0
ValliereMagic
A command line file cryptography tool

USAGE:
    mala_cryptor [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --decrypt <FILENAME>    specify a file to decrypt
    -e, --encrypt <FILENAME>    specify a file to encrypt
    -o, --output <FILENAME>     the target file to write the resultant file to
```
