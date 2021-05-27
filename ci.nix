{ pkgs ? import <nixpkgs> { } }:

with pkgs;
let
  binlore = callPackage ./default.nix { };
  # sudo = if pkgs.stdenv.isDarwin
  #   then pkgs.runCommand "sudo" { } ''
  #     mkdir -p $out/bin
  #     ln -s /usr/bin/sudo $out/bin/sudo
  #     ln -s /usr/sbin/sudo $out/bin/visudo
  #   '' else pkgs.sudo;
in
  binlore.collect { drvs = (import ./big.nix { }); }
  # binlore.collect { drvs = [ sudo ]; }
