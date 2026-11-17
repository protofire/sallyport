{
  description = "bridge_module — RFP-022 prototype Logos core module over bridge-core (private-only)";

  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [ "public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU=" ];
  };

  inputs = {
    logos-module-builder = {
      url = "github:logos-co/logos-module-builder";
      # The builder's pinned rust-overlay predates rustc 1.98.1 (needed by the LEZ v0.4 crates).
      inputs.rust-overlay.follows = "rust-overlay";
    };
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];

      # rust-lib/crates/* are symlinks into the repo's crates/ (one source of truth); the builder copies
      # rust-lib/ alone, so hand it a tree with real copies. Needs a git+file flake ref (see modules/nix-docker.sh).
      srcFor = system:
        nixpkgs.legacyPackages.${system}.runCommand "bridge-module-src" { } ''
          cp -r ${./.} $out
          chmod -R u+w $out
          rm -rf $out/rust-lib/crates $out/logos-rust-sdk-src
          mkdir -p $out/rust-lib/crates
          cp -r ${../../crates/bridge-core} $out/rust-lib/crates/bridge-core
          cp -r ${../../crates/consumers} $out/rust-lib/crates/consumers
          cp -r ${../../crates/attest-program} $out/rust-lib/crates/attest-program
          cp -r ${../../crates/inclusion} $out/rust-lib/crates/inclusion
          cp -r ${../../crates/lc-core} $out/rust-lib/crates/lc-core
        '';

      moduleFor = system: logos-module-builder.lib.mkLogosModule {
        src = srcFor system;
        configFile = ./metadata.json;
        flakeInputs = inputs;
      };
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system: (moduleFor system).packages.${system});
    };
}
