{ assume
, libarchive }:

assume libarchive {
  # i.e., if we see additions/deletions/changes to these, we
  # need a human to verify what's up.
  monitor = [
    /*
    TODO: I'm having trouble figuring out, from the libarchive source
    https://github.com/libarchive/libarchive/blob/0fd2ed25d78e9f4505de5dcb6208c6c0ff8d2edb/libarchive/filter_fork_posix.c#L141-L168
    */
  ];
  # # these triggered YARA, but don't result in arg subexec;
  # # it should be safe to exclude them from above treatment.
  # # Note: this is *just* documentary for now
  # ignore = [
  #   "execlp"
  #   "sys_spawn_shell"
  # ];
  # subexec_final = true;
  subexec_opts = [
    "--use-compress-program"
  ];
  combine_flags = false;
}
