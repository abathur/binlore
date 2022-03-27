{ pkgs ? import <nixpkgs> { } }:
with pkgs;
let
  rules = ./execers.yar;
  # sudo = if pkgs.stdenv.isDarwin
  #   then pkgs.runCommand "impure-native-darwin-sudo" { } ''
  #     mkdir -p $out/bin
  #     ln -s /usr/bin/sudo $out/bin/sudo
  #     ln -s /usr/sbin/sudo $out/bin/visudo
  #   '' else pkgs.sudo;
  # targets = [ sudo ];
  targets = (import ./big.nix { });
in runCommand "yara-matches" { } ''
  binlore_yara()(
    set -x
    ${yara}/bin/yara --scan-list --print-strings ${rules} <(printf '%s\n' $1/{bin,lib,libexec})
  )
  {
    echo ""
    for package in ${toString targets}; do
      echo "YARA rule matches for package $package"
      echo ""
      binlore_yara $package
      echo ""
      echo "File types"
      echo ""
      ${file}/bin/file -L $package/*/*
      echo ""
    done
  } > $out
  ''
