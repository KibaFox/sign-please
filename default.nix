with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "sign-please";
  buildInputs = [
    go
  ];
}
