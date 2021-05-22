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

  # yallback = callPackage (../yallback) {};
  yallback = callPackage (fetchFromGitHub {
    owner = "abathur";
    repo = "yallback";
    rev = "2768b5d81f7f3086b8a1399779bf6e7d3844dfe4";
    hash = "sha256-9VkHvqrj6YLTyKyQatZj9qZFpDjpQ1FU5fDOCbQ+KV8=";
  }) { };
}
