# Assumptions about commands

This whole directory tree is a bit of a WIP effort to fumble
towards good norms for documenting and maintaining what we
think we know about these commands.

This information forms the foundation of decisions we make
in binlore about whether to override the lore for popular
executables we've hand-verified don't subexec CLI args, and
for argument parsers that resholve carries for those that
can subexec their args.

> Note: 
> I'm choosing "assumptions" instead of "knowledge" because
> I want the language to _invite_ challenges from people who
> know better (or at least think they do).

## Fundamental problem
It's too expensive to update this 
info every time the nixpkgs hash changes, but the decisions 
based on this info *will* rot if we never revisit them as 
target programs evolve.

## Approach
From ~10K feet, I think this is about:
- Deciding what/how to document decisions made about which
  executables do/don't sub-exec to make it easier to iterate
  on those decisions in the future (to verify them, or when
  new information/versions are available).
- Figuring out how to distill as much of this as possible
  into checks/assertions that can automate much of the work
  of surfacing whatever needs human review/action.

I imagine that these will mostly converge on toward a single
practice/standard/format, but I separate them mostly because 
I expect automating to be a lot trickier than researching,
and don't want "what we can automate" to constrain what we
track/document.
