{ assume
, gnutar }:

assume gnutar {
  # i.e., if we see additions/deletions/changes to these, we
  # need a human to verify what's up.
  monitor = [
    "execv"
    "execvp"
    "execlp"
    "xexec"
    "sys_child_open_for_compress"
    "sys_child_open_for_uncompress"
    "sys_exec_command"
    "sys_exec_info_script"
    "sys_exec_checkpoint_script"
  ];
  # these triggered YARA, but don't result in arg subexec;
  # it should be safe to exclude them from above treatment.
  # Note: this is *just* documentary for now
  ignore = [
    "execlp"
    "sys_spawn_shell"
  ];
  # subexec_final = true;
  # subexec_opts = [];
  subexec_opts = [
    "-F"
    "--info-script"
    "--new-volume-script"
    "--to-commands"
    "--rsh-command"
    "--rmt-command"
    "-I"
    "--use-compress-program"
  ];
  # combine_flags = false;
}
