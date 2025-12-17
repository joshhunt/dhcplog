{
  description = "DHCP packet sniffer and logger";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          default = pkgs.buildGoModule {
            pname = "dhcplog";
            version = "0.1.0";

            src = ./.;

            vendorHash = "sha256-hn2C+6OihlMqMYZvGFpv5lIoj3ciqIq6Ykk1YzCHFbk=";

            ldflags = [ "-s" "-w" ];

            meta = with pkgs.lib; {
              description = "DHCP packet sniffer that logs DHCP traffic in logfmt";
              homepage = "https://github.com/joshhunt/dhcplog";
              license = licenses.mit;
              platforms = platforms.linux;
            };
          };
        };

        # Development shell with Go and dependencies
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gotools
            gopls
            go-tools
          ];

          shellHook = ''
            echo "dhcplog development environment"
            echo "Go version: $(go version)"
          '';
        };

        # Make the app runnable with `nix run`
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/dhcplog";
        };
      }
    );
}
