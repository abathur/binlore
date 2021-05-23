{ pkgs ? import <nixpkgs> { } }:

with pkgs;
let
  binlore = callPackage ./default.nix { };

in
  binlore.collect { drvs = [
    antlr
    asmfmt
    bc
    bison
    brotli
    bup
    bzip2
    clang
    cmake
    coloursum
    coreutils
    curl
    dash
    diffutils
    doxygen
    ed
    exa
    ffmpeg
    findutils
    fop
    fzf
    gawk
    gcc
    git
    gnugrep
    gnumake
    gnupatch
    gnused
    gzip
    htop
    jmespath
    jq
    less
    llvm
    loc
    lsof
    lynx
    man
    more
    ncurses
    ninja
    nmap
    openssh
    openvpn
    p7zip
    pass
    patch
    patchutils
    pcre
    perl
    php
    pstree
    python
    rsync
    rustc
    shellcheck
    shfmt
    smenu
    textql
    time
    tmate
    tmux
    unzip
    vault
    vim
    xz
    yacc
    yaml2json
  ]; }
