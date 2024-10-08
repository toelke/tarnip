let
  pkgs = import <nixpkgs> { };
in
pkgs.mkShell {
  buildInputs = [
    pkgs.cargo
    pkgs.rustc
    pkgs.libpcap
    pkgs.rustfmt
    pkgs.clippy
    pkgs.rust-analyzer
  ];
  shellHook = '''';
}
