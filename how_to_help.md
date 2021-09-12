# How to help

There are many meaningful ways to help out, many of which are fairly simple/granular. I've tried to break these down by what kind of knowledge they depend on. 

Don't hesitate to bug me for help breaking these down into more actionable steps. I'm trying to strike a balance between leaving too-few breadcrumbs, and making the list too-detailed for perusing. (I feel like it's already there, so I plan to move most of the specifics out into separate docs in the near future.)

## ~general UNIX knowledge
- Add more executable-bearing Nix packages to the CI run. See ()[big.nix]
    - Most helpful: executables from a previously-unrepresented script or compiled language ecosystem.
    - Helpful: packages with popular executables regardless of ecosystem. Maybe link to some real uses as proof, whether other uses in nixpgks or a GH search demonstrating the frequency of the most-common executable in the package:
        https://github.com/search?q=fzf+language%3Ashell+NOT+completion+NOT+bindings&type=code
    - Avoid:
        - packages that require slow local builds (unless they are the *only* way to add an unrepresented language ecosystem)
        - packages that have no vaguely-popular executables
- Audit executables that match the can_exec rule to see if the use of ~exec behavior is under user control or not.
    - Simply reporting your findings with the most-specific source links possible is already a big help. See assumptions.
    - You can also open a PR that adds a lore override script.

## Know any script/interpreted language
- Add basic YARA rules to identify any missing language(s) with known executables.
    - You can see what's already matched but not yet handled in the `rule unhandled` under ()[execers.yar]
    - The inverse smell is an executable matching might_exec that doesn't already match unhandled.
- Look at "handling" the language. Everything is meaningful. Is it possible? How hard? How many popular CLI programs use this language? If spotting exec is trivial, we'd might as well add it. Complex cases should be weighed relative to their frequency in the wild; it may be easier to manually review and override the individual executables.


## Dev, automation, testing
- Identify/extract/publish actionable info from CI runs. 
- Improve the safety of the lore override system.
    - Roughly, it could use some kind of safety mechanism to detect when its underlying assumptions are broken. On one hand, an executable marked safe by override could always gain not-safe behavior in the future. On the other, strict hash matching isn't really tenable. Some early thoughts:
    - a "dumb" way to do this is just a periodic re-review
    - Pushing lore overrides out of binlore and into the packages that need them may be tenable if/once binlore lands in nixpkgs. This doesn't _directly_ help, but it moves the lore closer to both people who know the package and the update process.

## Familiar with binary formats
- Review the existing YARA rules for formats you're familiar with.
- The current process only tests the executable itself (i.e., not any libraries or included modules). This is fine in many cases, but it does mean some executables have sub-exec behavior that it can't catch because they're implemented in a library.

    If you need an example/test-case of this behavior, you can look to bsdtar in libarchive. It currently gets marked as `cannot` by binlore, but [`__archive_create_child` within the actual libarchive component can run execvp or posix_spawnp](https://github.com/libarchive/libarchive/blob/0fd2ed25d78e9f4505de5dcb6208c6c0ff8d2edb/libarchive/filter_fork_posix.c#L141-L168). I haven't figured out the execution path, but I *assume* this is connected to the `--use-compression-program` option.

    binlore's low-resolution approach to searching for ~exec API functions means that uniformly tainting any executable that links the library is probably a step in the wrong direction. For example, /usr/lib/libSystem.B.dylib is both going to match for exec APIs and be ubiquitous on macOS.

- The current process is focused on common library calls that lead to exec instead of _direct_ syscalls. Library use is common and it's easy to spot the imported symbols. AIUI we'll need arch-specific detection for direct syscalls. I suspect this is straightforward for someone with good command of binary analysis and these formats.
- Report or add any missing formats that don't fit under the above rubric.

