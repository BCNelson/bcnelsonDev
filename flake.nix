{
  description = "Astro site with Pulumi infrastructure for bcnelson.dev";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    devenv.url = "github:cachix/devenv";
    systems.url = "github:nix-systems/default";
  };

  outputs = { self, nixpkgs, devenv, systems, ... } @ inputs:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages.x86_64-linux.devenv-up = self.devShells.x86_64-linux.default.config.procfileScript;

      devShells = forEachSystem (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };
        in
        {
          default = devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [
              {
                packages = with pkgs; [
                  nodejs_20
                  nodePackages.npm
                  just
                  python3
                  pulumi
                  wrangler
                  steam-run  # For running dynamically linked binaries (workerd)
                ];

                scripts.dev.exec = ''
                  steam-run npm run dev
                '';

                scripts.build.exec = ''
                  npm run build
                '';

                enterShell = ''
                  echo "bcnelson.dev development environment"
                  echo "Node: $(node --version)"
                  echo "Pulumi: $(pulumi version)"
                  echo ""
                  echo "Use 'dev' to start the dev server (runs via steam-run for workerd compatibility)"
                '';
              }
            ];
          };
        }
      );
    };
}
