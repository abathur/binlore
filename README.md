# binlore - generate and aggregate info about executables in nix packages

Since binlore is very young and currently has a limited scope, the vision may make a little more sense if I outline what it currently does and why. If you'd like to help improve binlore, see [How to help](how-to-help.md)

## Why / Motive
I'm building binlore to help [resholve](https://github.com/abathur/resholve) decide how likely the executables it finds in shell scripts are to also execute one of their arguments. 

This information helps resholve scrutinize these invocations more carefully and require user triage as-needed (without wasting user time on unlikely cases).

## What / API
binlore itself is a Nix API with two main functions:
- `make` which builds a derivation that runs a black-box we'll call `[analysis]` for a single package and outputs a directory with one or more named files containing some or all of the output from that analysis.
- `collect` which builds a derivation that depends on and aggregates the output of `make` for each package in a list. In this case, aggregation means concatenating files with the same name for every package into a single file of the same name.
- It'll take some use for norms/patterns to settle, but I tentatively see each file as a "type" or "kind" of lore.

## How / Analyses
The only `[analysis]` so far meets resholve's immediate needs. You can find its definition in the `loreDev` attr in [default.nix](default.nix), but the broad strokes are that it:
- runs YARA with a [single YARA ruleset](execers.yar) on `${package}/bin` 
- defines two "kinds" of lore (see [Lore Formats](#lore-formats) for detail): `execers`, and `wrappers`
- pipes the output through [yallback](https://github.com/abathur/yallback) (which supports shell callbacks for rule matches) using a [single callback script](execers.yall) to extract these two lore types

### Meta
I'm not sure what binlore's long-term relationship to individual analyses will be (or that the current abstractions are right).
- I suspect there may be utility in having a collection of standardized analyses that people can discover and apply without needing to understand enough to write one. This makes me want to collect them in binlore for now. (But there's no real mechanism yet--I don't want to fall into over-designing this until someone's asking.)
- But I also realize that needs may be too idiomatic for standardized analyses to ever be a good fit. If it smells like analyses are accumulating with no real re-use (no in-the-clear uses, re-use that almost always entails tweaking/adjusting an existing form, etc.)

## Lore Formats
There are currently two "kinds" of lore. In both cases below, the field separator is equivalent to `FIELD_SEPARATOR=$':'`:
- `$out/execers`, which has the format: `${verdict}${FIELD_SEPARATOR}${executable_path}` where:
    - `verdict=can|cannot|might`
    - `executable_path` is whatever path YARA printed for the match
- `$out/wrappers`, which has the format `${wrapper_path}${FIELD_SEPARATOR}${wrapped_path}` where:
    - `wrapper_path` is a path identified as a wrapper by YARA
    - `wrapped_path` is the path that the `shell_wrapper` yallback and `exec_target` function in `execers.yall` pick out of the source of the wrapper

## Usage / Examples
For now, at least, resholve's own uses of binlore should serve as a good example of the rough intent and usage:
- direct use for CI run: https://github.com/abathur/resholve/commit/52faf7493c51e5191de771eb49b8c12df90357cd#diff-783b1f6267f9b548283102092f66f71ac066b9e7b0917de0663e0269e1e26848R168
- similar use inside resholve's Nix API: https://github.com/abathur/resholve/commit/52faf7493c51e5191de771eb49b8c12df90357cd#diff-4ac4c92c1fad1b94f9defdc9f1c25bae0b446daa168078ce6e453ae7077a1908R80
