{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    gcc
    gdb
    valgrind
    pkg-config
    libpcap
    gnumake
  ];
}
