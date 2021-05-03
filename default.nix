{ pkgs ? import <nixpkgs> { }
}:

/* TODO/CAUTION:

I don't want to discourage use, but I'm not sure how stable
the API is. Have fun, but be prepared to track changes! :)

For _now_, binlore is basically a thin wrapper around
`<invoke yara> | <postprocess with yallback>` with support
for running it on a derivation, saving the result in the
store, and aggregating results from a set of packages.

In the longer term, I suspect there are more uses for this
general pattern (i.e., run some analysis tool that produces
a deterministic output and cache the result per package...).

I'm not sure how that'll look and if it'll be the case that
binlore automatically collects all of them, or if you'll be
configuring which "kind(s)" of lore it generates. Nailing
that down will almost certainly mean reworking the API.

*/

with pkgs;
let
  # override for macho and elf module improvements
  ouryara = yara.overrideAttrs(old: rec {
    version = "4.1.0";

    src = fetchFromGitHub {
      owner = "VirusTotal";
      repo = "yara";
      rev = "v${version}";
      hash = "sha256-j22I+KGb0z0wvrD/N+gQNUeAKQcDRTyggq7EG2aLg38=";
    };
    configureFlags = old.configureFlags ++ [ (lib.enableFeature true "macho") ];
    patches = [];
  });

  # yallback = callPackage (../yallback) {};
  yallback = callPackage (fetchFromGitHub {
    owner = "abathur";
    repo = "yallback";
    rev = "2768b5d81f7f3086b8a1399779bf6e7d3844dfe4";
    hash = "sha256-9VkHvqrj6YLTyKyQatZj9qZFpDjpQ1FU5fDOCbQ+KV8=";
  }) { };
  /*
  binlore has one one more yallbacks responsible for
  routing the appropriate lore to a named file in the
  appropriate format. At some point I might try to do
  something fancy with this, but for now the answer to
  *all* questions about the lore are: the bare minimum
  to get resholve over the next feature hump in time to
  hopefully slip this feature in before the branch-off.
  */
  # TODO: feeling really uninspired on the API
  loreDef = {
    # YARA rule file
    rules = ./execers.yar;
    # output filenames; "types" of lore
    types = [ "execers" "wrappers" ];
    # shell rule callbacks; see github.com/abathur/yallback
    yallback = ./execers.yall;
    # TODO:
    # - echo for debug, can be removed at some point
    # - I really just wanted to put the bit after the pipe
    #   in here, but I'm erring on the side of flexibility
    #   since this form will make it easier to pilot other
    #   uses of binlore.
    callback = lore: drv: ''
      echo "${ouryara}/bin/yara ${lore.rules} ${drv}/bin | ${yallback}/bin/yallback ${lore.yallback}"
      ${ouryara}/bin/yara ${lore.rules} ${drv}/bin | ${yallback}/bin/yallback ${lore.yallback}
    '';
  };

in rec {
  collect = { lore ? loreDef, drvs }: (runCommand "more-binlore" { } ''
    mkdir $out
    for lorefile in ${toString lore.types}; do
      cat ${lib.concatMapStrings (x: x + "/$lorefile ") (map (make lore) drvs)} > $out/$lorefile
    done
  '');
  # TODO: echo for debug, can be removed at some point
  make = lore: drv: runCommand "${drv.name}-binlore" { } ''
    mkdir $out
    touch $out/{${builtins.concatStringsSep "," lore.types}}
    echo generating binlore for ${drv} by running:
    ${lore.callback lore drv}
    echo binlore written to $out
  '';
}
