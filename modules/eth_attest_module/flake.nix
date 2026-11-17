{
  description = "eth_attest_module — RFP-021 Logos core module: produce / dry-run-verify light-client-backed Ethereum attestations";

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
    # Ethereum consensus-layer access goes through the Logos Ethereum core module (RFP requirement).
    # Consumed as its LIDL contract: the builder generates modules().beacon_api_module from it.
    beacon_api_module = {
      url = "github:logos-co/logos-evm-beacon-api-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    # ...and so does execution-layer access. Routing per call is inclusion::host::el_route:
    # headers and block receipts through verified_proxy_module (light-client verified),
    # eth_getProof through eth_rpc_module.raw_rpc (the proxy does not expose it).
    eth_rpc_module = {
      url = "github:logos-co/logos-evm-eth-rpc-module/b39bebf3a2e0801d8272aeb0da04ed172719955f";
      inputs.logos-module-builder.follows = "logos-module-builder";
      inputs.verified_proxy_module.follows = "verified_proxy_module";
    };
    # 0.1.8: beacon providers from beacon_api_module, Sepolia execution default = ethpandaops (proof history).
    verified_proxy_module = {
      url = "github:logos-co/logos-verified-proxy-module/1e15ae40c18b6144a385cafcea32bf52466629f6";
      inputs.logos-module-builder.follows = "logos-module-builder";
      inputs.beacon_api_module.follows = "beacon_api_module";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];

      # rust-lib/crates/{lc-core,inclusion,lez-client,attest-program} are symlinks into the repo's crates/ (one source of truth,
      # local `cargo test` works). The builder copies rust-lib/ on its own, which would leave them
      # dangling, so hand it a source tree with real copies. Requires a git+file flake ref (the repo
      # root must be in the flake source for ../../crates to resolve); see modules/nix-docker.sh.
      srcFor = system:
        nixpkgs.legacyPackages.${system}.runCommand "eth-attest-module-src" { } ''
          cp -r ${./.} $out
          chmod -R u+w $out
          rm -rf $out/rust-lib/crates $out/logos-rust-sdk-src
          mkdir -p $out/rust-lib/crates
          cp -r ${../../crates/lc-core} $out/rust-lib/crates/lc-core
          cp -r ${../../crates/inclusion} $out/rust-lib/crates/inclusion
          cp -r ${../../crates/lez-client} $out/rust-lib/crates/lez-client
          cp -r ${../../crates/attest-program} $out/rust-lib/crates/attest-program
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
