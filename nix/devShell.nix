{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    gcc
    gdb
    valgrind
    meson
    ninja
    pkg-config
    libpcap
  ];
}
