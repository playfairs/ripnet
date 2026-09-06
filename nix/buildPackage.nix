{ pkgs, lib, stdenv }:

stdenv.mkDerivation {
  pname = "ripnet";
  version = "1.0.0";

  src = ./.;

  nativeBuildInputs = with pkgs; [
    meson
    ninja
    pkg-config
  ];

  buildInputs = with pkgs; [
    libpcap
  ];

  meta = with lib; {
    description = "Network diagnostics, packet analysis, observability, and authorized load-testing toolkit";
    homepage = "https://github.com/playfairs/ripnet";
    license = licenses.gpl3Only;
    platforms = platforms.linux ++ platforms.darwin;
    mainProgram = "ripnet";
  };
}
