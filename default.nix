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
  inherit (callPackage ./deps.nix { }) ouryara yallback;
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
      echo generating binlore for $drv by running:
      echo "${ouryara}/bin/yara ${lore.rules} ${drv}/bin | ${yallback}/bin/yallback ${lore.yallback}"
      ${ouryara}/bin/yara ${lore.rules} ${drv}/bin | ${yallback}/bin/yallback ${lore.yallback}
    '';
  };
  overrides = ./overrides;

in rec {
  collect = { lore ? loreDef, drvs }: (runCommand "more-binlore" { } ''
    mkdir $out
    for lorefile in ${toString lore.types}; do
      cat ${lib.concatMapStrings (x: x + "/$lorefile ") (map (make lore) drvs)} > $out/$lorefile
    done
  '');
  # TODO: echo for debug, can be removed at some point
  make = lore: drv: runCommand "${drv.name}-binlore" {
      identifier = drv.name;
      drv = drv;
    } (''
    mkdir $out
    touch $out/{${builtins.concatStringsSep "," lore.types}}
    '' +
    /*
    Override lore for some packages. Unsure, but for now:
    1. start with the ~name (pname-version)
    2. remove characters from the end until we find a match
       in overrides/
    3. execute the override script with the list of expected
       lore types
    */
    ''
    i=''${#identifier}
    while [[ $i > 0 ]]; do
      ((i--)) || true # don't break build
      if [[ -f "${overrides}/''${identifier:0:$i}" ]]; then
        echo using "${overrides}/''${identifier:0:$i}" to generate overriden binlore for $drv
        ${bash}/bin/bash "${overrides}/''${identifier:0:$i}" ${toString lore.types}
        break
      fi
    done # || true # don't break build
    if [[ $i == 0 ]]; then
      ${lore.callback lore drv}
    fi
    echo binlore written to $out
  '');
}
