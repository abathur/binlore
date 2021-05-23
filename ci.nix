{ pkgs ? import <nixpkgs> { } }:

with pkgs;
let
  binlore = callPackage ./default.nix { };

in
  binlore.collect { drvs = (import ./big.nix {}); }
