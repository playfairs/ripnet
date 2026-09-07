{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    ldc
    nox
    gdb
    valgrind
    ninja
    pkg-config
    libpcap
  ];
}
