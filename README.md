# binlore - generate and aggregate info about executables in nix packages

Since binlore is very young and currently has a limited scope, the vision may make a little more sense if I outline what it currently does and why.

1. I'm building binlore to help [resholve](https://github.com/abathur/resholve) decide how likely the executables it finds in shell scripts are to also execute one of their arguments. 

    This information helps resholve scrutinize these invocations more carefully and require user triage as-needed (without wasting the user time on unlikely cases).

2. binlore itself is a Nix API with two main functions:
    - `make` which builds a derivation that runs a black-box we'll call `[analysis]` for a single package and outputs a directory with one or more named files containing some or all of the output from that analysis.
    - `collect` which builds a derivation that depends on and aggregates the output of `make` for each package in a list. In this case, aggregation means concatenating files with the same name for every package into a single file of the same name.
    - It'll take some use for norms/patterns to settle, but I tentatively see each file as a "type" or "kind" of lore.

3. the only `[analysis]` so far meets resholve's immediate needs:
    - runs YARA with a [single YARA ruleset](execers.yar) on `${package}/bin` 
    - pipes the output through [yallback](https://github.com/abathur/yallback) (which supports shell callbacks for rule matches) using a [single callback script](execers.yall) to extract two "kinds" of lore:
        - `$out/execers`, which has the format: `${verdict}${FIELD_SEPARATOR}${executable_path}` where:
            - `verdict=can|cannot|might`
            - `FIELD_SEPARATOR=$':'`
            - and `executable_path` is whatever path YARA printed for the match
        - `$out/wrappers`, which has the format `${wrapper_path} -> ${wrapped_path}`
            - not using this yet, so the format is even more likely to change

    I'm not certain what relationship binlore will have to individual analyses. I'd like it to be easy to add analyses.

4. resholve's own uses of binlore serve as a good example of the rough intent
    - direct use for CI run: https://github.com/abathur/resholve/commit/52faf7493c51e5191de771eb49b8c12df90357cd#diff-783b1f6267f9b548283102092f66f71ac066b9e7b0917de0663e0269e1e26848R168
    - similar use inside resholve's Nix API: https://github.com/abathur/resholve/commit/52faf7493c51e5191de771eb49b8c12df90357cd#diff-4ac4c92c1fad1b94f9defdc9f1c25bae0b446daa168078ce6e453ae7077a1908R80
