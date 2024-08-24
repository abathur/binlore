# Changelog

## v0.5.0 (August 24, 2024)
- Add new nix function `binlore.synthesize` for generating override lore.
- Update lore collector to support collecting from `drv.passthru.binlore` and `$out/nix-support/<lorefile>`.

    (The latter is laying groundwork for trying to update nixpkgs' makeWrapper* functions to output their own authoritative wrapper lore.)

- Migrate lore overrides from this repo to nixpkgs.

> Caution: Due to their nature, the changes in this release were developed directly in nixpkgs and ported back here once stable.
>
> This (and the desire to avoid hitting staging for changes that otherwise don't affect behavior of the non-Nix parts of binlore) means there's a fairly long period of mismatch between what's here and what's in nixpkgs.
>
> These will likely remain out of sync until we touch the relevant source here (the YARA rules and hooks to process YARA's output).

## v0.4.0 (March 22, 2024)
- Revert fix for cross builds, which proved unnecessary once a better fix was implemented up at the resholve/nixpkgs level.

> Caution: This tracks a Nix API fix implemented first in Nixpkgs. I did not bump the source version in nixpkgs to avoid a staging cycle for a no-op change.

## v0.3.0 (March 20, 2024)
- Refactor nix code and adopt flakes.
- Add overrides for nixos-install-tools and nixos-rebuild.
- Update overrides for cctools, llvm, and procps.
- Fix cross builds.

## v0.2.0 (April 7, 2022)
- Collect lore for lib and libexec as well
- Collect lore recursively (largely for lib+libexec)
- Identify (but don't handle) Ruby scripts.
- Reduce false-positives for shell_wrapper rule.
- Accept a "strip" list of pkgs and strip matching
  prefixes off of each lore line. (This is for making
  lore "relative". See resholve's changelog for a bit
  more on the higher-level motive.)

## v0.1.4 (Jan 28 2022)
- add ncurses and zip overrides

## v0.1.2 & v0.1.3 (Sep 12 2021)
- add [how-to-help doc](how_to_help.md)
- add libarchive override

## v0.1.1 (Sep 10 2021)
Use getBin on collected drvs (instead of drv directly). Not certain about this; may need relitigating.

## v0.1.0 (Aug 10 2021)
Initial release.
