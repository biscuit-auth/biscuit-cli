{ pkgs ? import <unstable> {}}: with pkgs;

mkShell {
  buildInputs = [
    openssl
    rustup
    pkg-config
    zlib
  ];
}
