# Biscuit CLI

This package provides a Command Line Interface allowing to manipulate [biscuit](https://github.com/CleverCloud/biscuit) tokens.

## Installation

This package is not published on [crates.io](https://crates.io) yet, so you need to build it locally:

```
git clone https://github.com/biscuit-auth/biscuit-cli.git
cd biscuit-cli
cargo install --path .
```

## Use

The executable carries contextual help, you can run `biscuit help` to list available commands, and `biscuit help <command>` to get help about a specific command.

All the commands support reading keys, datalog and tokens from various sources, such as files, options, or stdin.

All the commands can be used in a script, and the commands where you can provide datalog (`generate`, `inspect` and `attenuate`) can also be used in an interactive way,
where a text editor (`$EDITOR`) is started to let you input a datalog program from within a comfortable environment.

By default keys and biscuits are read and written as hex-encoded and base64-encoded strings, but the CLI supports working with raw bytes directly with dedicated flags.

**Just make sure you don't leak sensitive information like private keys in your shell history**

Here are a list of common use-cases:

### Generate a key pair

```
$ # this will output the keypair, you can then copy/paste the components
$ biscuit keypair
> Generating a new random keypair
> Private key: 4aa4bae701c6eb05cfe0bdd68d5fab236fc0d0d3dcb2a9b582a0d87b23e04500
> Public key: 687b536c502f10f5978eee2d0c04f2869d15cf7858983dc50b6729b15e203809

$ # this will save the private key to a file so you can use it later
$ biscuit keypair --only-private-key > private-key-file
```

### Generate a public key from a private key

```
$ biscuit keypair --from-private-key-file private-key-file --only-public-key
> 94cbe231b05dac8ae556c39a3cdc3d12103ad9ed5500eda6098c60e6672bf858
```

### Create a biscuit token

```
$ # this will open your text editor and let you type in the authority block as datalog
$ biscuit generate --private-key-file private-key-file
> ChcIADgBQhEKDwgEEgIIABIHIgVmaWxlMRoglMviMbBdrIrlVsOaPNw9EhA62e1VAO2mCYxg5mcr-FgiRAogKAZh5JjRh6n3UTQIVlptzWsAhj92UaOjWZQOVYYqaTASIFG7bXx0Y35LjRWcJHs7N6CAEOBJOuuainDg4Rg_S8IG

$ # this will generate the token directly 
$ echo 'right(#authority, "file1");' | biscuit generate --private-key-file pkf -
ChcIADgBQhEKDwgEEgIIABIHIgVmaWxlMRoglMviMbBdrIrlVsOaPNw9EhA62e1VAO2mCYxg5mcr-FgiRAogCCirktOm6gYKHHnjyQ49L7u2YOyxfi9gPQ0q_5_bRXASIBeYUocb2BHGgS3-GJCmgq1sk26YH439UhvnsScrXz4H
```

### Inspect a biscuit token

By default, `biscuit` inspect only prints out the biscuit contents (datalog blocks, and revocation ids).

```
$ # this will inspect the token stored in the given file
$ biscuit inspect biscuit-file
>
> Authority block:
> == Datalog ==
> right(#authority, "file1");
> 
> == Revocation ids ==
> Content-based: de8704ebf3fbd43a976b92c7ae21b396ca9dd493d4ebf95d3a9e899c58587024
> Unique:        4523e74599e34ab3fa79822f4c213526aa7fcab5d3a84e177d0c4ef92adc482b
> 
> ==========
```

A public key can be provided to check the biscuit root key (the command exits with a success code only if the keys match)

```
$ # this will make sure the biscuit root key is the same as the one that's provided
$ biscuit inspect --public-key-file public-key-file biscuit-file
> Authority block:
> == Datalog ==
> right(#authority, "file1");
> 
> == Revocation ids ==
> Content-based: de8704ebf3fbd43a976b92c7ae21b396ca9dd493d4ebf95d3a9e899c58587024
> Unique:        4523e74599e34ab3fa79822f4c213526aa7fcab5d3a84e177d0c4ef92adc482b
> 
> ==========
> 
Public key check succeeded
```

A verifier can be provided to check if the biscuit would be allowed in a given context (the command exits with a success code only if the keys match and if the verification suceeded).

If you want to use your text editor to type in the verifier, you can use `--verify-interactive` instead.

```
$ biscuit inspect --public-key-file public-key-file \
                  --verify-with 'allow if right(#authority, "file1");' \
                  biscuit-file 
> Authority block:
> == Datalog ==
> right(#authority, "file1");
> 
> == Revocation ids ==
> Content-based: de8704ebf3fbd43a976b92c7ae21b396ca9dd493d4ebf95d3a9e899c58587024
> Unique:        4523e74599e34ab3fa79822f4c213526aa7fcab5d3a84e177d0c4ef92adc482b
> 
> ==========
> 
> Public key check succeeded
> Datalog check succeeded
```

### Attenuating a biscuit token

```
# this will create a new biscuit token with the provided block appended
$ biscuit attenuate biscuit-file --block 'check if time(#ambient, $0), $0 <= 2021-07-29T14:06:43+00:00;'
> ChcIADgBQhEKDwgEEgIIABIHIgVmaWxlMRJACAESBXF1ZXJ5EgR0aW1lEgEwOAFSKgooCgIIBxIKCAgSAggBEgIQCRoWCgQKAhAJCggKBiiU7IqIBgoEGgIIAhoglMviMbBdrIrlVsOaPNw9EhA62e1VAO2mCYxg5mcr-FgaIM7CFNnvFB-SeN-VhpPRtZJnUzFM918XulzU8OL1pIc7ImYKIAgoq5LTpuoGChx548kOPS-7tmDssX4vYD0NKv-f20VwCiA-zkpZZjA5vLa-8XL8p6oXvf5A-rUCIcHOyPWR3aogdhIgzB0tA9eSatJU0NiQnQW7HgSr0fjnQqJ4ccKHZlrj-w4=
```
