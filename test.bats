setup() {
    if brew --prefix; then
        TEST_BREW_PREFIX="$(brew --prefix)"
        load "${TEST_BREW_PREFIX}/lib/bats-support/load.bash"
        load "${TEST_BREW_PREFIX}/lib/bats-assert/load.bash"
    elif [ "${GITHUB_ACTIONS}" == "true" ]; then
        load "/usr/lib/bats-support/load.bash"
        load "/usr/lib/bats-assert/load.bash"
    fi
    cargo build
    PATH="./target/debug:${PATH}"
}

# this makes sure we're testing the correct biscuit executable
@test "the correct biscuit version is selected" {
    run which biscuit
    assert_output --partial "target/debug"
}

# the following tests make sure that there is no clap configuration error
@test "biscuit --help runs without crashing" {
    biscuit --help
}
@test "biscuit append-third-party-block --help runs without crashing" {
    biscuit append-third-party-block --help
}
@test "biscuit attenuate --help runs without crashing" {
    biscuit attenuate --help
}
@test "biscuit generate --help runs without crashing" {
    biscuit generate --help
}
@test "biscuit generate-request --help runs without crashing" {
    biscuit generate-request --help
}
@test "biscuit generate-third-party-block --help runs without crashing" {
    biscuit generate-third-party-block --help
}
@test "biscuit inspect --help runs without crashing" {
    biscuit inspect --help
}
@test "biscuit inspect-snapshot --help runs without crashing" {
    biscuit inspect-snapshot --help
}
@test "biscuit keypair --help runs without crashing" {
    biscuit keypair --help
}
@test "biscuit seal --help runs without crashing" {
    biscuit seal --help
}
