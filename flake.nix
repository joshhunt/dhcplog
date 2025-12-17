{
  description = "DHCP packet sniffer and logger";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # NixOS module for dhcplog service
      nixosModule = { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.services.dhcplog;
        in
        {
          options.services.dhcplog = {
            enable = mkEnableOption "DHCP packet sniffer and logger";

            interface = mkOption {
              type = types.str;
              default = "eth0";
              description = "Network interface to capture DHCP packets on";
            };

            package = mkOption {
              type = types.package;
              default = self.packages.${pkgs.system}.default;
              defaultText = literalExpression "self.packages.\${pkgs.system}.default";
              description = "The dhcplog package to use";
            };
          };

          config = mkIf cfg.enable {
            systemd.services.dhcplog = {
              description = "DHCP packet sniffer and logger";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];

              serviceConfig = {
                ExecStart = "${cfg.package}/bin/dhcplog -i ${cfg.interface}";
                Restart = "always";
                RestartSec = "5s";

                # Security hardening
                DynamicUser = true;
                AmbientCapabilities = [ "CAP_NET_RAW" "CAP_NET_ADMIN" ];
                CapabilityBoundingSet = [ "CAP_NET_RAW" "CAP_NET_ADMIN" ];
                NoNewPrivileges = true;
                PrivateTmp = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [ "AF_PACKET" "AF_INET" "AF_INET6" ];
                RestrictNamespaces = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                PrivateMounts = true;
              };
            };
          };
        };
    in
    {
      # Export the NixOS module
      nixosModules.default = nixosModule;
      nixosModules.dhcplog = nixosModule;
    }
    //
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
