{ lib, callPackage, fetchFromGitHub, yara, }:

{
  # yallback = callPackage (../yallback) { };
  yallback = callPackage (fetchFromGitHub {
    owner = "abathur";
    repo = "yallback";
    rev = "v0.2.0";
    hash = "sha256-t+fdnDJMFiFqN23dSY3TnsZsIDcravtwdNKJ5MiZosE=";
  }) { };
}
