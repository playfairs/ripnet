{ pkgs, lib, stdenv }:

stdenv.mkDerivation {
  pname = "ripnet";
  version = "1.0.0";

  src = ./.;

  nativeBuildInputs = with pkgs; [
    pkg-config
    make
  ];

  buildInputs = with pkgs; [
    libpcap
  ];

  makeFlags = [ "PREFIX=$(out)" ];

  installPhase = ''
    mkdir -p $out/bin
    cp bin/ripnet $out/bin/
    chmod +x $out/bin/ripnet
  '';

  meta = with lib; {
    description = "Network diagnostics, packet analysis, observability, and authorized load-testing toolkit";
    homepage = "https://github.com/playfairs/ripnet";
    license = licenses.gpl3Only;
    platforms = platforms.linux ++ platforms.darwin;
    mainProgram = "ripnet";
  };
}
