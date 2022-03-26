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

rule executable //private
{
    condition:
        magic.type() contains "executable" or magic.type() contains "shared library"
}

rule shared_object //private
{
    condition:
        magic.type() contains "shared object"
}

/*
Note: an unreadable setuid executable (like sudo) won't have the
      expected type string and won't otherwise be readable
*/
rule macho_binary //private
{
    condition:
        executable and magic.type() contains "Mach-O "
}

rule elf_binary //private
{
    condition:
        (executable or shared_object) and magic.type() contains "ELF "
}

rule elf_binary_static //private
{
    condition:
        elf_binary and magic.type() contains "statically linked"
}

/* TODO:
- "GLIBC" might be able to separate further if needed
- since these can syscall, we need to at least figure out if they do
  (even if we don't try to figure out that they syscall execve(at))
*/
rule elf_binary_dynamic //private
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
        executable and magic.type() matches /script.*?(text|binary data)/
}

rule shell_script
{
    condition:
        script and magic.type() matches /(POSIX shell|Bourne-Again shell|\/bin\/\w*sh)\s*[-a-z]{,2}\s*script/
}

rule shell_wrapper
{
    strings:
        $ = /exec\s+((-a \S+|-c|-l|-E)\s+)*["']{0,1}[^'"]{2,100}["']{0,1}/
    condition:
        shell_script and any of them
}

// Might find wrappers in many other forms, I guess.
rule wrapper
{
    condition:
        shell_wrapper
}

rule python_script //private
{
    condition:
        script and magic.type() matches /(Python|\/bin\/python\S*) script/
}

rule perl_script //private
{
    condition:
        script and magic.type() matches /(Perl|\/bin\/perl\S*) script/
}

rule node_script //private
{
    condition:
        // I'm not certain the first form is possible, but
        // I'll use it for symmetry/just-in-case
        script and magic.type() matches /(Node|\/bin\/node\S*) script/
}

rule php_script //private
{
    condition:
        script and magic.type() matches /(PHP|\/bin\/php\S*) script/
}

rule ruby_script //private
{
    condition:
        script and magic.type() matches /(Ruby|\/bin\/ruby\S*) script/
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
    strings:
        // TODO: AFAIK all I need is the below, but it's worth testing whether a naive
        // string match on execve as a precondition helps this miss faster?
        //            e  x  e  c  v  e
        $_execve = { 65 78 65 63 76 65 }
        //           e  x  e  c  l
        $_execl = { 65 78 65 63 6c }
        //            e  x  e  c  l  p
        $_execlp = { 65 78 65 63 6c 70 }
        //            e  x  e  c  l  e
        $_execle = { 65 78 65 63 6c 65 }
        //           e  x  e  c  t
        $_exect = { 65 78 65 63 74 }
        //           e  x  e  c  v
        $_execv = { 65 78 65 63 76 }
        //            e  x  e  c  v  p
        $_execvp = { 65 78 65 63 76 70 }
        //            e  x  e  c  v  P
        $_execvP = { 65 78 65 63 76 50 }
        //           p  o  p  e  n
        $_popen = { 70 6f 70 65 6e}
        //                 p  o  s  i  x  _  s  p  a  w  n
        $_posix_spawn = { 70 6f 73 69 78 5f 73 70 61 77 6e }
        //                  p  o  s  i  x  _  s  p  a  w  n  p
        $_posix_spawnp = { 70 6f 73 69 78 5f 73 70 61 77 6e 70 }
        //            s  y  s  t  e  m
        $_system = { 73 79 73 74 65 6d }
    condition:
        // can be a more compact RE, but let's focus
        // on being explicit/clear for now
        any of them and elf_binary and for any sym in elf.dynsym : (sym.name matches /^(execl|execlp|execle|execlp|execv|execve|execveat|execvp|execvpe|fexecve|popen|posix_spawn|posix_spawnp|system)$/)
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
    //                @   _  e  x  e  c  v  e
    $_execve = { (00|40) 5F 65 78 65 63 76 65 (00|24) }
    //               @   _  e  x  e  c  l
    $_execl = { (00|40) 5F 65 78 65 63 6c (00|24) }
    //                @   _  e  x  e  c  l  p
    $_execlp = { (00|40) 5F 65 78 65 63 6c 70 (00|24) }
    //                @   _  e  x  e  c  l  e
    $_execle = { (00|40) 5F 65 78 65 63 6c 65 (00|24) }
    //               @   _  e  x  e  c  t
    $_exect = { (00|40) 5F 65 78 65 63 74 (00|24) }
    //               @   _  e  x  e  c  v
    $_execv = { (00|40) 5F 65 78 65 63 76 (00|24) }
    //                @   _  e  x  e  c  v  p
    $_execvp = { (00|40) 5F 65 78 65 63 76 70 (00|24) }
    //                @   _  e  x  e  c  v  P
    $_execvP = { (00|40) 5F 65 78 65 63 76 50 (00|24) }
    //               @   _  p  o  p  e  n
    $_popen = { (00|40) 5F 70 6f 70 65 6e (00|24)}
    //                     @   _  p  o  s  i  x  _  s  p  a  w  n
    $_posix_spawn = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e (00|24) }
    //                      @   _  p  o  s  i  x  _  s  p  a  w  n  p
    $_posix_spawnp = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e 70 (00|24) }
    //                @   _  s  y  s  t  e  m
    $_system = { (00|40) 5F 73 79 73 74 65 6d (00|24) }

    /*
    We want to assert some control over where these can match as substrings.
    Initially I thought we could do this by always 00-terminating them, but
    I've found at least one example (gnu-sed) where they're terminated with
    $DARWIN_EXTSN.

    I guess for now we'll assert *either* 00 or $ at the end of each match.

    I'm doing this to avoid repeating a large variable-length branch to end
    each string (and to DRY a bit), but this may be premature optimization.

    TODO: when this feels settled, simplify the condition and append darwin
    extsn from below to every string to see if there's a noteworthy net effect
    */
    $DARWIN_EXTSN = { 24 44 41 52 57 49 4e 5f 45 58 54 53 4e } private
    // $nul = { 00 } private


    //$mac = { ?? ?? ?? 65 78 65 63 76 65 ?? ?? ??}
    condition:
        any of them and for any of ($_*) : ( uint8(@ + ! - 1) == 0x00 or $DARWIN_EXTSN at (@ + ! - 1) ) and macho_binary and for any segment in macho.segments: (segment.segname == "__LINKEDIT" and for any of them : ($ in (segment.fileoff..(segment.fileoff + segment.fsize))))
        //($popen and  at (@popen + !popen - 1)) or (all of them)
        // any of them and binary
        //for any of them : ( @ - 1 == @DARWIN_EXTSN  ) and binary
}

// old rule before current experiment
// rule macho_execve
// {
//     strings:
//     // idk which form is more desirable; first is obviously
//     // more self-documenting
//     //$mac = "@_execve" fullword
//     //405f 6578 6563 7665 00
//     //                  p?
//     //405f 6578 6563 7670 // there may be a normative 00 here as well?
//     // 2767040, 3335140?
//     // $mac = { 40 5F 65 78 65 63 76 65 00 }
//     // (781800..781900), (893300..893400), (899600..899700),
//     //$mac = "execve"
//     //         @   _  e  x  e  c  v  e
//     $ = { (00|40) 5F 65 78 65 63 76 65 00 }
//     //         @   _  e  x  e  c  l
//     $ = { (00|40) 5F 65 78 65 63 6c 00 }
//     //         @   _  e  x  e  c  l  p
//     $ = { (00|40) 5F 65 78 65 63 6c 70 00 }
//     //         @   _  e  x  e  c  l  e
//     $ = { (00|40) 5F 65 78 65 63 6c 65 00 }
//     //         @   _  e  x  e  c  t
//     $ = { (00|40) 5F 65 78 65 63 74 00 }
//     //         @   _  e  x  e  c  v
//     $ = { (00|40) 5F 65 78 65 63 76 00 }
//     //         @   _  e  x  e  c  v  p
//     $ = { (00|40) 5F 65 78 65 63 76 70 00 }
//     //         @   _  e  x  e  c  v  P
//     $ = { (00|40) 5F 65 78 65 63 76 50 00 }
//     //         @   _  p  o  p  e  n
//     $ = { (00|40) 5F 70 6f 70 65 6e 00 }
//     //         @   _  p  o  s  i  x  _  s  p  a  w  n
//     $ = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e 00 }
//     //         @   _  p  o  s  i  x  _  s  p  a  w  n  p
//     $ = { (00|40) 5F 70 6f 73 69 78 5f 73 70 61 77 6e 70 00 }
//     //         @   _  s  y  s  t  e  m
//     $ = { (00|40) 5F 73 79 73 74 65 6d 00 }


//     //$mac = { ?? ?? ?? 65 78 65 63 76 65 ?? ?? ??}
//     condition:
//         binary and for any segment in macho.segments: (segment.segname == "__LINKEDIT" and for any of them : ($ in (segment.fileoff..(segment.fileoff + segment.fsize))))
// }

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

rule elf_cannot_exec
{
    condition:
        elf_binary and not (go_exec or elf_execve)
}

rule go_cannot_exec
{
    condition:
        go_binary and not go_exec
}

/*
The intent of these 'abstract' rules is to let the concrete rules
just *try* to describe/reflect what they *try* to measure
without having to worry about also reflecting confidence and
quality in their conditions.
*/

/*
For now, this only gatekeeps *cannot* decisions. While the
other decisions are ~important, too, "cannot" is the only
one that resholve won't make the user triage, so it'll be
harder to notice problems with it (and more consequential).

This rule expresses the conditions we feel reasonably sure
we can judge correctly.
*/
rule decidable : abstract
{
    condition:
        macho_binary or elf_binary or go_binary // or decidable_shell
        /*
        note: macho but not ELF because dynamic linking and libsystem
        make me a lot more confident about whether the rudimentary
        analysis used here is able to find most things that exec; in
        ELF we also need to be able to find arbitrary direct syscalls
        across multiple formats?
        */
}

/*
This rule enumerates conditions that we are *identifying*
but not yet explicitly addressing. In some cases we'll do
this because we later intend to address the condition, or
because we need to identify the condition just to exclude
it from some other context.
*/
rule unhandled : abstract
{
    condition:
        perl_script or (shell_script and not shell_wrapper) or python_script or node_script or php_script or ruby_script
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
*/
// can|cannot|might|tbd
rule can_exec
{
    condition:
        execve
}

rule cannot_exec
{
    condition:
        decidable and (macho_cannot_exec or elf_cannot_exec or go_cannot_exec)
}

/*
Open to a better name here, as I'm afraid it'll be easy to
confuse this with the practice of marking anything that can't
be confidently decided as can/cannot into might.

The current narrow purpose of tbd is for wrappers, which
we have to separately analyze to figure out what they wrap,
and then take the decision of that executable.
*/
rule tbd_exec
{
    condition:
        wrapper
}

rule might_exec
{
    condition:
        executable and not cannot_exec and not can_exec and not tbd_exec
}

/*
TODO: (caution: documenting this retroactively by several weeks)
Just sort of documenting what's going on below since it
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
a fidelity improvement later if we find someone with the chops to do
this with high confidence or find real cases where an exec sneaks in
through this gap.

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
