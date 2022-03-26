{ pkgs ? import <nixpkgs> { } }:

with pkgs; [
    yara
    pass
    patch
    perl
    zip
]
