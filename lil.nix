{ pkgs ? import <nixpkgs> { } }:

with pkgs; [
    neovim
    yara
    pass
    patch
    perl
    zip
]
