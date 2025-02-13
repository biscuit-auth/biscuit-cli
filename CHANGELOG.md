# `0.6.0-beta.1`

- biscuit-auth 6.0.0-beta.1
  - biscuit-datalog v3.3 support
  - ECDSA signatures support
  - policy snapshots support
- display datalog version in blocks

# `0.5.0`

- biscuit-auth 5.0.0

# `0.4.2`

- display evaluation time & iterations (#54)
- biscuit-auth 4.1.1 (better authorizer contents listing) (#55)
- `nix develop` support for local dev (#56) (er4hn)

# `0.4.1`

- support for querying authorizers and snapshots (#45)
- internal refactor, fix displayed version number (#46)
- support for running authorization on a snapshot (#47)
- biscuit-auth 4.0.0 (#50)
- JSON output in `biscuit inspect` (#48)
- JSON output in `biscuit inspect-snapshot` (#51)

# `0.4.0`

- support for viewing and setting root key ids (#41)
- improved syntax for datalog parameter injection (#42)
- biscuit-auth 3.2.0

# `0.3.0`

- better errors (#25, #28)
- support for third-party tokens (#27)
- support for parameter interpolation in datalog (#29)
- fix regressions after biscuit-auth update (#30) (Sébastien Allemand)
- configurable run limitations (#34)
- rename `verifier` to `authorizer` (#36)
- support for generating and inspecting authorizer snapshots (#33)
- support for sealing biscuits (#26)
- `--add-ttl` now supports timestamps in addition to durations (#39)
