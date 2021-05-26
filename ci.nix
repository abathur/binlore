{ pkgs ? import <nixpkgs> { } }:

with pkgs;
let
  binlore = callPackage ./default.nix { };
  sudo = if pkgs.stdenv.isDarwin
    then pkgs.runCommand "impure-native-darwin-sudo" { } ''
      mkdir -p $out/bin
      ln -s /usr/bin/sudo $out/bin/sudo
    '' else pkgs.sudo;

in
  binlore.collect { drvs = (import ./big.nix { inherit sudo; }); }
  # binlore.collect { drvs = [ sudo ]; }
