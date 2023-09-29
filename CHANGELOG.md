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
