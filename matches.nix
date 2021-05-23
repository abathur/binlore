{ pkgs ? import <nixpkgs> { } }:
with pkgs;
let
  inherit (pkgs.callPackage ./deps.nix { }) ouryara;
  rules = ./execers.yar;
  targets = (import ./big.nix {});
in runCommand "yara-matches" { } ''
  binlore_yara()(
    set -x
    ${ouryara}/bin/yara --print-strings ${rules} $1
  )
  {
    echo ""
    for package in ${toString targets}; do
      echo "YARA rule matches for package $package"
      echo ""
      binlore_yara $package/bin
      echo ""
      echo "File types"
      echo ""
      ${file}/bin/file -L $package/bin/*
      echo ""
    done
  } > $out
  ''
