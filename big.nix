{ pkgs ? import <nixpkgs> { } }:

with pkgs; [
    ag
    antlr
    /*
    the networking unixtools all need an env to
    permit openssl 1.0.2 and then end up triggering
    a *build* of that openssl that takes several minutes
    (so long that basically everything else that doesn't
    depend on this has been long-since finished; ~8
    minutes in this specific run).

    I am letting this complete a single time in CI, noting
    the result here, and then disabling these to save time
    in the future. (all are cannot_exec on both platforms)
    */
    # unixtools.arp
    apacheHttpd
    asmfmt
    bash
    bat
    bc
    bison
    brotli
    bup
    bzip2
    clang
    cmake
    unixtools.col
    coloursum
    unixtools.column
    coreutils
    curl
    dash
    dig
    diffutils
    docker
    doxygen
    ed
    emacs
    # esh # probably needs to wait for file 5.41+
    exa
    unixtools.fdisk
    ffmpeg
    findutils
    fop
    unixtools.fsck
    fzf
    gawk
    gcc
    unixtools.getconf
    unixtools.getent
    unixtools.getopt
    git
    gnugrep
    gnumake
    # gnupatch # defer to generic patch for now
    gnupg
    gnused
    gnutar
    grc
    gzip
    heroku
    unixtools.hexdump
    unixtools.hostname
    htop
    hub
    # unixtools.ifconfig
    j2cli
    jmespath
    jq
    unixtools.killall
    kubectl
    less
    libarchive
    llvm_5
    llvm_6
    llvm_7
    llvm_8
    llvm_9
    llvm_10
    llvm_11
    loc
    unixtools.locale
    lsof
    lynx
    man
    unixtools.more
    unixtools.mount
    nano
    ncurses
    neovim
    # unixtools.netstat
    nginx
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
    # php temp disable tue may 25; for some reason this is building suddenly, and it eats a fair chunk of build time
    # unixtools.ping
    unixtools.ps
    pstree
    python
    unixtools.quota
    ranger
    rlwrap
    # unixtools.route
    rsync
    ruby
    rustc
    screen
    unixtools.script
    shellcheck
    shfmt
    smenu
    socat
    sqlite
    # sudo disabled because nix+sudo doesn't work like this; it needs a wrapper and isn't cross-platform
    unixtools.sysctl
    textql
    time
    tmate
    tmux
    unixtools.top
    tree
    unixtools.umount
    unzip
    vagrant
    vault
    vim
    unixtools.watch
    wget
    unixtools.whereis
    unixtools.write
    unixtools.xxd
    xz
    yaml2json
    yarn
    youtube-dl
    zsh
    zip
] ++ lib.optionals (!stdenv.isDarwin) [
    pacman
    unixtools.eject
    unixtools.logger
    unixtools.wall
] ++ lib.optionals (stdenv.isLinux) [
    util-linux
]
