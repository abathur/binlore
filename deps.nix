{ lib, callPackage, fetchFromGitHub, yara, }:

{
  ouryara = yara.overrideAttrs(old: rec {
    version = "4.1.0";

    src = fetchFromGitHub {
      owner = "VirusTotal";
      repo = "yara";
      rev = "v${version}";
      hash = "sha256-j22I+KGb0z0wvrD/N+gQNUeAKQcDRTyggq7EG2aLg38=";
    };
    configureFlags = old.configureFlags ++ [ (lib.enableFeature true "macho") ];
    patches = [];
  });

  # yallback = callPackage (../yallback) { };
  yallback = callPackage (fetchFromGitHub {
    owner = "abathur";
    repo = "yallback";
    rev = "dfbc12e6155b21de74d09bf9d6e384ee16b71c03";
    hash = "sha256-QkkL23zSSM3bXJY/ReRkDycMeuU5OkufL7dmaGeeFqY=";
  }) { };
}
