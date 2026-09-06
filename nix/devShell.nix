{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    ldc
    gdb
    valgrind
    meson
    ninja
    pkg-config
    libpcap
  ];
}
