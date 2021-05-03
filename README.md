# binlore - generate and aggregate info about executables in nix packages

Since binlore is very young and currently has a limited scope, the vision may make a little more sense if I outline what it currently does and why.

1. binlore is one of a few tools I'm prototyping to help [resholve](https://github.com/abathur/resholve) decide how likely the executables it finds in shell scripts are to also execute one of their arguments. 

    This information will help resholve scrutinize invocations of these executables more carefully and require user triage as-needed (without wasting the user's energy on unlikely cases).

2. binlore itself is a Nix API with two main functions:
    - `make` which builds a derivation that runs a black-box we'll call `[analysis]` for a single package and outputs a directory with one or more named files containing some or all of the output from that analysis.
    - `collect` which builds a derivation that depends on and aggregates the output of `make` for each package in a list. In this case, aggregation means concatenating files with the same name for every package into a single file of the same name.
    - It'll take some use for norms/patterns to settle, but I tentatively see each file as a "type" or "kind" of lore.

3. the only `[analysis]` so far meets resholve's immediate needs:
    - runs YARA with a [single YARA ruleset](execers.yar) on `${package}/bin` 
    - pipes the output through [yallback](https://github.com/abathur/yallback) (which supports shell callbacks for rule matches) using a [single callback script](execers.yall) to extract two "kinds" of lore:
        - `$out/execers`, which has the format: `${verdict}${UNIT_SEPARATOR}${executable_path}` where:
            - `verdict=can|cannot|might`
            - `UNIT_SEPARATOR=$'\x1f'`
            - and `executable_path` is whatever path YARA printed for the match
        - `$out/wrappers`, which has the format `${wrapper_path} -> ${wrapped_path}`
            - not using this yet, so the format is even more likely to change
