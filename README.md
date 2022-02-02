# Biscuit CLI

This package provides a Command Line Interface allowing to manipulate [biscuit](https://github.com/biscuit-auth/biscuit) tokens.

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
> Private key: d1e3ebc3f522cc2f7bb40c2377830d834c41ebeb0aa54d881a75059704dfa6cb
> Public key: 80c596ea5a6ade1a2f8e7bf96359732d9274789d8e85c0a0a62adbff16f4b289

$ # this will save the private key to a file so you can use it later
$ biscuit keypair --only-private-key > private-key-file
```

### Generate a public key from a private key

```
$ biscuit keypair --from-private-key-file private-key-file --only-public-key
> 2341bc530d8f074100734a41cc05cc82e4e2564eff61b0408f8e37a08f384767
```

### Create a biscuit token

```
$ # this will open your text editor and let you type in the authority block as datalog
$ biscuit generate --private-key-file private-key-file
> En0KEwoFZmlsZTEYAiIICgYIBBICGAcSJAgAEiB-So8adTv5YLBK49I8MrK1JdrYLrFSiFqUkRkVsco9MhpAJzlkr2xHM4JSlFmph7c9UEJPqw_BCscMgkIasAjnXZT5BHpA58M1uo_4KUDbPZSJVtbF93P43X41W7aofjZXAiIiCiCScR0e_rBUa7VjxnKW4PT52ZjC3peMCrWOi1T0jgR0fw==

$ # this will generate the token directly
$ echo 'right("file1");' | biscuit generate --private-key-file private-key-file -
$ En0KEwoFZmlsZTEYAiIICgYIBBICGAcSJAgAEiDg91H1_yfDSMrLnfXLowUZsKJDfrC-1XVSPkbikXYy7BpAacFHci_m8X3PffAgeEXVgF3RvwzhE434KWLNpbDYLE1_IOIwsSjRVqFC4fy-NuY9CEqetJ8fHUfo0I7Qs05TDSIiCiDHkAX0s3RgH_wMYDKlE09S2YZM-1cLmFgl5Nh3gvU0bg==
```

### Inspect a biscuit token

By default, `biscuit` inspect only prints out the biscuit contents (datalog blocks, and revocation ids).

```
$ # this will inspect the token stored in the given file
$ biscuit inspect biscuit-file
> Authority block:
> == Datalog ==
> right("file1");
> 
> == Revocation id ==
> 526c78ffa3819cb71bcade69d6d78f80ad1209f21d2c3326857c66ca8fc19c63a4283929b690ae40ca8474594631caee464b0367b781d3cc1139343c13900509
> 
> ==========
> 
> 🙈 Public key check skipped 🔑
> 🙈 Datalog check skipped 🛡️
```

A public key can be provided to check the biscuit root key (the command exits with a success code only if the keys match)

```
$ # this will make sure the biscuit root key is the same as the one that's provided
$ biscuit inspect --public-key-file public-key-file biscuit-file
> Authority block:
> == Datalog ==
> right("file1");
> 
> == Revocation id ==
> 526c78ffa3819cb71bcade69d6d78f80ad1209f21d2c3326857c66ca8fc19c63a4283929b690ae40ca8474594631caee464b0367b781d3cc1139343c13900509
> 
> ==========
> 
> ✅ Public key check succeeded 🔑
> 🙈 Datalog check skipped 🛡️
```

A verifier can be provided to check if the biscuit would be allowed in a given context (the command exits with a success code only if the keys match and if the verification suceeded).

If you want to use your text editor to type in the verifier, you can use `--verify-interactive` instead.

```
$ biscuit inspect --public-key-file public-key-file \
                  --verify-with 'allow if right(#authority, "file1");' \
                  biscuit-file
> Authority block:
> == Datalog ==
> right("file1");
> 
> == Revocation id ==
> 526c78ffa3819cb71bcade69d6d78f80ad1209f21d2c3326857c66ca8fc19c63a4283929b690ae40ca8474594631caee464b0367b781d3cc1139343c13900509
> 
> ==========
> 
> ✅ Public key check succeeded 🔑
> ✅ Authorizer check succeeded 🛡️
> Matched allow policy: allow if right("file1")
```

### Attenuating a biscuit token

```
# this will create a new biscuit token with the provided block appended
$ biscuit attenuate biscuit-file --block 'check if client_ip_address("127.0.0.1);'
> En0KEwoFZmlsZTEYAiIICgYIBBICGAcSJAgAEiBrhbrvPUXH9RPOzIwnLVyRWwcK64JQ97kBvz1hLJfjfBpAUmx4_6OBnLcbyt5p1tePgK0SCfIdLDMmhXxmyo_BnGOkKDkptpCuQMqEdFlGMcruRksDZ7eB08wROTQ8E5AFCRqhAQo3CgVxdWVyeQoRY2xpZW50X2lwX2FkZHJlc3MKCTEyNy4wLjAuMRgCMg4KDAoCCAgSBggJEgIYChIkCAASIL6EGw7TZQ-8sRa0RT1U0cW8mjN_GzoW0jwX_67I0zPCGkDL5ho8NPsZwskzJ86e31qR29grjcEQormtv7I3YoQy_I2aoZGNtlviX72FuBT85KlVxJtjOiLxCIOvJj4MVN0KIiIKIM6btYoZ-ONE2gKEJ2raR8Bck7SMBAUf2sK7Z8I7uM_D
```
