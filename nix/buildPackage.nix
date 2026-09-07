{
  pkgs,
  lib,
  stdenv,
  nox,
}:

stdenv.mkDerivation {
  pname = "ripnet";
  version = lib.removeSuffix "\n" (builtins.readFile ../VERSION);

  src = builtins.path {
    path = ../.;
    name = "ripnet-source";
  };

  nativeBuildInputs = [
    pkgs.ldc
    nox.packages.${stdenv.hostPlatform.system}.default
    pkgs.pkg-config
  ];

  buildInputs = [ pkgs.libpcap ];

  configurePhase = "true";

  buildPhase = ''
    export PATH=${pkgs.ldc}/bin:${pkgs.pkg-config}/bin:$PATH
    ${nox.packages.${stdenv.hostPlatform.system}.default}/bin/nox setup build --release
    ${nox.packages.${stdenv.hostPlatform.system}.default}/bin/nox build build -j$NIX_BUILD_CORES
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp build/release/ripnet/ripnet $out/bin/ripnet
  '';

  meta = with lib; {
    description = "Network diagnostics, packet analysis, observability, and authorized load-testing toolkit";
    homepage = "https://github.com/playfairs/ripnet";
    license = licenses.gpl3Only;
    platforms = platforms.linux ++ platforms.darwin;
    mainProgram = "ripnet";
  };
}
