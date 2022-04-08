# Changelog

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
