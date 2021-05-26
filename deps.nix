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
    rev = "28d625874596dddacdf4923bd25308ed26e36709";
    hash = "sha256-v7q9no9Fj+vY44TwpDimvvjUFxdkntGUIZXpqgXU5dE=";
  }) { };
}
