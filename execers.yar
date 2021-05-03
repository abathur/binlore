/*
The broad strokes are something like:
- treat the set of all ~executables (I've seen at least
  one command id as a shared object) as if they *could* exec
  some arbitrary executable from their arguments
- carve out subsets where we can accurately separate those
  that "might" (in reality) exec from those that *will not*
  in order to spare users from having to triage those that
  will not. this is a little nuanced:
  - because we have user triage as a backstop, it's fine to
    have a lot of false positives, as long as we have ~zero
    false negatives
  - we can get away with very crude heuristics, but we do
    need to be able to understand where they are useless. an
    example may help. on macOS, golang binaries have to be
    dynamically-linked and use libsystem, so we *can* detect
    undefined libsystem exec wrappers as a clue that one may
    exec. on Linux, the same binaries might be dynamic or
    static--we might find libc wrappers OR raw syscalls. we
    have to do a little more work on the linux set to know
    that we can reliably separate the no|maybe execs.
  - priority: size of subset + how easy it is to handle

Other notes/context:
- first time (expect beginner mistakes) working with/on:
    - binary formats/analysis
    - yara
- I would greatly appreciate help nit-picking the strings
  and patterns (pare strings that always match together,
  fix/cull incorrect ones, generalize, etc).
  - However: don't worry about unused rules for now; they
    are stubs made before I knew where the MVP cutoff was.
- I don't understand (haven't tried to investigate) the perf
  implications of using libmagic/magic module to drive many
  of these decisions. For now I'm focused on clarity. If
  this really is a big performance headwind, at some point
  I may be open to converting them back into magic strings,
  with the caveat that *I* want to avoid being on the hook
  for directly curating a collection of magic strings.
- I haven't really decided what the ~public API of this
  ruleset is yet. There will likely be renames and rules
  made private.
  - aside: I have a vague sense that I'd eventually like for
    rules (whether they're used at all, and public/private)
    to be configurable (at least for performance reasons).
*/

import "magic"
import "elf"
import "macho"

private rule executable
{
    condition:
        magic.type() contains "executable" or magic.type() contains "shared library"
}

private rule shared_object
{
    condition:
        magic.type() contains "shared object"
}

/*
Note: an unreadable setuid executable (like sudo) won't have the
      expected type string and won't otherwise be readable
*/
private rule macho_binary
{
    condition:
        executable and magic.type() contains "Mach-O "
}

private rule elf_binary
{
    condition:
        (executable or shared_object) and magic.type() contains "ELF "
}

private rule elf_binary_static
{
    condition:
        elf_binary and magic.type() contains "statically linked"
}

/* TODO:
- "GLIBC" might be able to separate further if needed
- since these can syscall, we need to at least figure out if they do
  (even if we don't try to figure out that they syscall execve(at))
*/
private rule elf_binary_dynamic
{
    condition:
        elf_binary and magic.type() contains "dynamically linked"
}

rule binary
{
    condition:
        elf_binary or macho_binary
}

rule go_binary
{
    // TODO:
    // - convert to hex
    // - add conditional underscore
    // - match nul bytes
    // these are also present in both versions (but w/o underscore)
    // __gosymtab
    // __gopclntab
    strings:
        $gosymtab = "gosymtab"
        $gopclntab = "gopclntab"
        //               g  o  .  b  u  i  l  d  i  d
        $buildid = { 00 67 6f 2e 62 75 69 6c 64 69 64 00 }
    condition:
        binary and 1 of them //or magic.type() contains "Go BuildID"
}

rule elf_binary_dynamic_glibc
{
    strings:
        $ = "GLIBC"
    condition:
        elf_binary_dynamic and any of them
}

rule elf_binary_dynamic_unexpected_noglibc
{
    condition:
        elf_binary_dynamic and not elf_binary_dynamic_glibc
}

rule script
{
    condition:
        executable and magic.type() matches /script.*?text/
}

rule shell_script
{
    condition:
        script and magic.type() matches /(POSIX shell|\/bin\/\w*sh)\s*[-a-z]{,2}\s*script/
}

rule shell_wrapper
{
    strings:
        $ = /exec\s+(-a \S+|-c|-l)\s+["']{0,1}[^'"]{2,100}["']{0,1}/
    condition:
        shell_script and any of them
}

private rule python_script
{
    condition:
        script and magic.type() matches /(Python|\/bin\/python\S*) script/
}

/*
TODO: I'm not in a hurry, but eventually I'd like to support the top N
scripting languages in here as well, to the extent possible? In the
meantime, we can still bikeshed over the right number for N, and add
rules to match the languages.
*/

rule symlink
{
    condition:
        magic.type() contains "symbolic link to"
}

rule go_exec
{
    strings:
        $ = "exec_unix.go"
        $ = "os/exec"
        $ = "os/exec.(*Cmd).Run" // seems to produce good results all by itself, at least on gotools
        // same but hex
        $ = { 6f 73 2f 65 78 65 63 2e 28 2a 43 6d 64 29 2e 52 75 6e } // os/exec.(*Cmd).Run
        // I've seen another source also specify:
        $ = "os/exec.(*Cmd).Start"
        // TODO: there are probably more forms of this, but IDK if any are needed...
        //    48 c7 04 24 3b 00 00    movq   $0x3b,(%rsp)
        $ = { 48 c7 04 24 3b 00 00 }
    condition:
        go_binary and 1 of them
}

// strings:
//         //  00 6578 6563 7665 00 // seems to *usually* be surrounded by 00;
//         // be aware that this could also be padding (but it looks stableish)
//         // note, the @@GLIBC is the part that'll get stripped; don't be tempted to rely on it
//         // $elf = "execve"
//         //           e  x  e  c  v  e      @ @
//         $elf = { 00 65 78 65 63 76 65 (00|4040) }
rule elf_execve
{
    // TODO: AFAIK all I need is the below, but it's worth testing whether a naive
    // string match on execve as a precondition helps this miss faster?
    condition:
        // can be a more compact RE, but let's focus
        // on being explicit/clear for now
        binary and for any sym in elf.dynsym : (sym.name matches /^(execl|execlp|execle|execlp|execv|execve|execveat|execvp|execvpe|fexecve|popen|posix_spawn|posix_spawnp|system)$/)
}

rule macho_execve
{
    strings:
    // idk which form is more desirable; first is obviously
    // more self-documenting
    //$mac = "@_execve" fullword
    //405f 6578 6563 7665 00
    //                  p?
    //405f 6578 6563 7670 // there may be a normative 00 here as well?
    // 2767040, 3335140?
    // $mac = { 40 5F 65 78 65 63 76 65 00 }
    // (781800..781900), (893300..893400), (899600..899700),
    //$mac = "execve"
    //            @   _  e  x  e  c  v  e
    $ = { (00|40) 5F 65 78 65 63 76 65 00 }
    //            @   _  e  x  e  c  l
    $ = { (00|40) 5F 65 78 65 63 6c 00 }
    //            @   _  e  x  e  c  l  p
    $ = { (00|40) 5F 65 78 65 63 6c 70 00 }
    //            @   _  e  x  e  c  l  e
    $ = { (00|40) 5F 65 78 65 63 6c 65 00 }
    //            @   _  e  x  e  c  t
    $ = { (00|40) 5F 65 78 65 63 74 00 }
    //            @   _  e  x  e  c  v
    $ = { (00|40) 5F 65 78 65 63 76 00 }
    //            @   _  e  x  e  c  v  p
    $ = { (00|40) 5F 65 78 65 63 76 70 00 }
    //            @   _  e  x  e  c  v  P
    $ = { (00|40) 5F 65 78 65 63 76 50 00 }
    //            @   _  p  o  p  e  n
    $ = { (00|40) 5F 70 6f 70 65 6e 00 }
    //            @   _  p  o  s  i  x  _  s  p  a  w  n
    $ = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e 00 }
    //            @   _  p  o  s  i  x  _  s  p  a  w  n  p
    $ = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e 70 00 }
    //            @   _  s  y  s  t  e  m
    $ = { (00|40) 5F 73 79 73 74 65 6d 00 }


    //$mac = { ?? ?? ?? 65 78 65 63 76 65 ?? ?? ??}
    condition:
        binary and for any segment in macho.segments: (segment.segname == "__LINKEDIT" and for any of them : ($ in (segment.fileoff..(segment.fileoff + segment.fsize))))
}

rule execve
{
    condition:
        go_exec or elf_execve or macho_execve
}

rule macho_cannot_exec
{
    condition:
        macho_binary and not macho_execve
}

rule decidable
{
    condition:
        macho_binary// or decidable_shell
        /*
        note: macho but not ELF because dynamic linking and libsystem
        make me a lot more confident about whether the rudimentary
        analysis used here is able to find most things that exec; in
        ELF we also need to be able to find arbitrary direct syscalls
        across multiple formats?
        */
}

/*
TODO:
- I'd like to drop the _exec suffix from all of these at some point
  because it'll bring the format in line with what resholve wants.
  However, I am delaying this decision until I have a better sense of
  the full scope of binlore and its rule-config/modularity options?

  I want to avoid circumstances where a single output:
  - has rule namespace clashes
  - combines rules in a way that make can|cannot|might painfully vague

- I have a format sketch that also used "unknown" but in practice (at
  least for resholve) any executable that isn't "can" or "cannot"
  should go be "might".

  I imagined "unknown" disambiguated "we have no rules for trying to
  make principled decisions about this" from "might". It would still
  need to be treated as "might" for this top-line use--but maybe there
  will eventually be some value in discriminating?
*/
// can|cannot|might
rule can_exec
{
    condition:
        execve
}

rule cannot_exec
{
    condition:
        decidable and macho_cannot_exec
}

rule might_exec
{
    condition:
        executable and not cannot_exec and not can_exec
}

/*
TODO: (caution: documenting this retroactively by several weeks)
Just sort of documenting what's going on here since this is half-done,
may or may not be useful, and is roughly half-done. I was picking at
the question of how we'd figure out if anything uses a dylib that
exposes any API for ~exec behavior.

If I recall, I stalled out here after I figured out that we'd kinda
need to map these recursively and maintain some sort of whitelist of
libs that are known to be safe all the way down, and know what the
unsafe API calls are for any we know aren't safe, and then either have
a mechanism for analyzing one-off libraries similarly, or just assume
they're unsafe?

In any case, I don't want to get bogged down chasing this; it can be
a fidelity improvement later if there are real cases found where it
is missing an exec?

FWIW: look carefully at perl; I have tabs open with hexdumps of perl
that I think are from the timeframe when I was looking at this, so it
is at least possible that I knew I had one of these cases in perl and
have since forgotten.

real goal: "we have a dylib that isn't known to be safe", since at least a few are likely to be common + safe?
*/
// rule this_unnamed_rule_means_we_have_a_dylib_other_than_libsystem
// {
//     strings:
//         $libsystem = { 00 2F 75 73 72 2F 6C 69 62 2F 6C 69 62 53 79 73 74 65 6D 2E 42 2E 64 79 6C 69 62 00 }
//         $dylib = { 00 2f [6-111] 2e 64 79 6c 69 62 00 }
//     condition:
//         @dylib != @libsystem and (@dylib < macho.entry_point or @dylib < macho.segments[0].sections[0].offset)
//         //macho_binary and not (
//         // for any of them : ( @ < macho.entry_point and $ == "/usr/lib/libSystem.B.dylib" )
//         // $libsystem and $dylib and ($dylib not at $libsystem) and $dylib in (0..macho.entry_point)
//         // and for any x in macho.file: (x.ncmds == 0x0000000c)
// }
