{ pkgs ? import <nixpkgs> { }
}:

/* DOING:

This is just a bit of ideation about how to start racheting
the ~assumptions/assumptions binlore and resholve make about
commands into testable assertions that we can regularly run
to be informed of breaks.

I think this will (internally or externally) need some kind
of re-do-all-of-these options.

Broad summary so far:
- generatePatches tries to generate a patch that knocks out
  calls for all of the API functions in the "monitor" list
  from the individual default.nix files
- testAssumptions fails if it can't apply such patches, or
  if anything in assumptions/package/*.test fails.
- generateIntel kicks out WIP ~research products. For now
  these are mostly just exploring what we can generate, how
  much information we need to do so, how best to encode it,
  and so on. For now these include plaintext copies of the
  manpage, and a stub python parser for resholve.

I might run one of these like:
nix-build assumptions -A libarchive.intel
*/

with pkgs;
let
  binlore = callPackage
    (fetchFromGitHub {
      owner = "abathur";
      repo = "binlore";
      rev = "v0.1.1";
      hash = "sha256-EOWxKC8daHTWQdl/KiQbJ3zXWOKGMHNho+gERDF8YUk=";
    })
    { };
  common = { drv, ... }@attrs: stdenv.mkDerivation ((removeAttrs attrs [ "monitor" "ignore" ]) // {
    src = drv.src;
    assumptions = (./. + "/${drv.pname}/");
    checkInputs = [ patch gnugrep ];
    dontBuild = true;
    dontConfigure = true;
    doCheck = true;
    dontInstall = true;
    dontFixup = true;
  });
  testAssumptions = drv: attrs: common {
    inherit drv;
    name = "test-assumptions-of-${drv.name}";
    prePatch = ''
      echo $PWD
      ls
      echo assumptions=$assumptions
      ls $assumptions
      shopt -s nullglob
      patches=$assumptions/*.patch
    '';
    checkPhase = ''
      echo $PWD
      ls
      grepscript(){
        for fn in $@; do
          echo "$fn\s*\("
        done
      }
      if grep -rlE --file=<(grepscript ${builtins.concatStringsSep " " attrs.monitor}); then
        echo ruhroh!
        exit 3
      fi
      for fact in $assumptions/*.test; do
        bash $fact
      done
      touch $out
    '';
  };
  generatePatches = drv: attrs: common {
    inherit drv;
    name = "assumption-patches-for-${drv.name}";
    prePatch = ''
      mkdir $out
      sedscript(){
        for fn in $@; do
          echo "s/$fn\s*(/ewgross(/"
        done
      }
      grepscript(){
        for fn in $@; do
          echo "$fn\s*\("
        done
      }
      patches_the_kitten(){
        while read -r result; do
          diff --color --unified $result --label a/$result --label b/$result <(sed -f <(sedscript $@) $result)
        done < <(grep -rlE --file=<(grepscript $@))
      }

      cat > $out/commitment_device.patch <<PATCH
      magic pretend header
      ---

      $(patches_the_kitten ${builtins.concatStringsSep " " attrs.monitor})
      --
      2.31.1 TODO
      PATCH

      if [[ -e $out/commitment_device.patch ]]; then
        :
        # make sure it applies
        patch -p1 --dry-run < $out/commitment_device.patch; echo $?
      fi
    '';
  };
  generateIntel = drv: attrs: common {
    inherit drv;
    name = "intel-for-${drv.name}";
    buildInputs = [ gzip groff coreutils unixtools.col ];
    inherit (attrs) combine_flags subexec_opts;
    lore = binlore.collect { drvs = [drv]; };
    /* TODO
    - subexec_opts should be per executable
    - I think we can skip enumerating all short flags IF the
      only subexec is behind options and NONE of those opts
      have short flags
    - I suspect we have to enumerate all of the flags for
      final-arg executors like env.
    - It'd be nice to start generating overrides from here
    - subexec_opts should get dropped from the ignore flags
    */
    checkPhase = ''
      mkdir $out
      plaintext_man(){
        if gzip -cd $1 | groff -m man -T utf8 >/dev/null; then
          gzip -cd $1 | groff -m man -T utf8 | col -bx
        elif gzip -cd $1 | groff -m mdoc -T utf8 >/dev/null; then
          gzip -cd $1 | groff -m mdoc -T utf8 | col -bx
        fi
      }
      generate_parser(){
        echo "
          @staticmethod
          def _$1():
              generic = CommandParser("\"$1\"")
      $(generate_args $1 $2)
              return (generic,)
        "
      }
      generate_arg(){
        echo '        generic.add_argument('
        for arg in $(tr '\n' ' '); do
          echo "            \"$arg\","
        done
        for arg in "$@"; do
          echo "            $arg,"
        done
        echo '        )'
      }
      generate_args(){
        if [[ -s short_opts_with_args_$1 ]]; then
          generate_arg 'dest="arg_ignored"' \
            'nargs=1' < short_opts_with_args_$1
        fi
        if [[ -s short_opts_without_$1 ]]; then
          generate_arg 'dest="argless_ignored"' \
            'action="store_true"' < short_opts_without_$1
        fi

        # final
        if [[ $subexec_final == 1 ]]; then
          generate_arg '"commands"' \
            'action="invocations"' \
            'nargs=theirparse.REMAINDER' < <(:)
        fi

        # flag
        if [[ -n $subexec_opts ]]; then
          generate_arg 'dest="commands"' \
            '# split=True, # if it word-splits on exec' \
            'action="invocations"' \
            'nargs=1' < <(echo ${builtins.concatStringsSep " " attrs.subexec_opts})
        fi
      }
      manhandle(){
        if [[ "$2" == "1" ]]; then
          grep -Po '^\s*-[^-](?=(,|\s).*?=)' man_$1 > short_opts_with_args_$1
          grep -Po '^\s*-[^-](?!(,|\s).*?=)' man_$1 > short_opts_without_$1
        fi
        generate_parser "$1" "$2"
      }

      for manpage in ${lib.getMan drv}/share/man/man1/*; do
        cmdname=''${manpage/*\//} # strip path
        cmdname=''${cmdname/.*/} # strip extension
        plaintext_man $manpage > man_$cmdname
        cp man_$cmdname $out/man_$cmdname
        manhandle $cmdname $combine_flags > $out/parse_$cmdname || true
      done
    '';
  };
  assume = drv: attrs: {
    test = testAssumptions drv attrs;
    patch = generatePatches drv attrs;
    intel = generateIntel drv ({ combine_flags = true; subexec_final = false; subexec_opts = []; } // attrs);
  };
  presume = thing: callPackage thing { inherit assume; };

in {
  # see gnutar/default.nix for more
  # maybe better for these to just be files?
  gnutar = presume ./gnutar;
  libarchive = presume ./libarchive;
}

