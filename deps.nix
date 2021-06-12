{ lib, callPackage, fetchFromGitHub, yara, }:

{
  # yallback = callPackage (../yallback) { };
  yallback = callPackage (fetchFromGitHub {
    owner = "abathur";
    repo = "yallback";
    rev = "dfbc12e6155b21de74d09bf9d6e384ee16b71c03";
    hash = "sha256-QkkL23zSSM3bXJY/ReRkDycMeuU5OkufL7dmaGeeFqY=";
  }) { };
}
