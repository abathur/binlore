{ lib, callPackage, fetchFromGitHub, yara, }:

{
  # yallback = callPackage (../yallback) { };
  yallback = callPackage (fetchFromGitHub {
    owner = "abathur";
    repo = "yallback";
    rev = "v0.1.0";
    hash = "sha256-FaPqpxstKMhqLPFLIdenHgwzDE3gspBbJUSY95tblgI=";
  }) { };
}
