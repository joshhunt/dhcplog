//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

func dhcpMessageType(dhcp *layers.DHCPv4) layers.DHCPMsgType {
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptMessageType && len(opt.Data) == 1 {
			return layers.DHCPMsgType(opt.Data[0])
		}
	}
	return 0
}

func dhcpHostname(dhcp *layers.DHCPv4) string {
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptHostname {
			return string(opt.Data)
		}
	}
	return ""
}

func dhcpRequestedIP(dhcp *layers.DHCPv4) string {
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptRequestIP && len(opt.Data) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", opt.Data[0], opt.Data[1], opt.Data[2], opt.Data[3])
		}
	}
	return ""
}

func formatDHCPOptionValue(opt layers.DHCPOption) string {
	// Use the built-in String() method and extract just the value part
	// The format is "Option(TYPE:VALUE)" so we extract the value
	str := opt.String()

	// Find the colon and closing paren
	colonIdx := -1
	for i, c := range str {
		if c == ':' {
			colonIdx = i
			break
		}
	}

	if colonIdx == -1 || colonIdx >= len(str)-2 {
		// Fallback: just show hex
		return fmt.Sprintf("%x", opt.Data)
	}

	// Extract the value between : and )
	value := str[colonIdx+1 : len(str)-1]
	return value
}

func logfmt(k string, v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return ""
		}
		// quote only if needed
		for _, c := range val {
			if c == ' ' || c == '"' {
				return fmt.Sprintf(`%s="%s"`, k, val)
			}
		}
		return fmt.Sprintf("%s=%s", k, val)
	default:
		return fmt.Sprintf("%s=%v", k, v)
	}
}

func main() {
	iface := flag.String("i", "enp4s0", "Interface to capture on")
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	log.Printf("msg=starting_dhcp_sniffer interface=%s", *iface)

	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(*iface),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(1<<20),
		afpacket.OptNumBlocks(16),
	)
	if err != nil {
		log.Fatalf("msg=afpacket_init_failed err=%v", err)
	}
	defer h.Close()

	for {
		data, ci, err := h.ZeroCopyReadPacketData()
		if err != nil {
			log.Printf("msg=read_error err=%v", err)
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp := udpLayer.(*layers.UDP)

		if !((udp.SrcPort == 67 || udp.SrcPort == 68) && (udp.DstPort == 67 || udp.DstPort == 68)) {
			continue
		}

		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			continue
		}
		dhcp := dhcpLayer.(*layers.DHCPv4)

		msgType := dhcpMessageType(dhcp)
		host := dhcpHostname(dhcp)
		reqIP := dhcpRequestedIP(dhcp)

		srcIP, dstIP := "?", "?"
		if net := packet.NetworkLayer(); net != nil {
			srcIP = net.NetworkFlow().Src().String()
			dstIP = net.NetworkFlow().Dst().String()
		}

		ts := ci.Timestamp.UTC().Format(time.RFC3339Nano)

		// Build logfmt line
		fields := []string{
			logfmt("ts", ts),
			logfmt("msg", msgType.String()),
			logfmt("src", fmt.Sprintf("%s:%d", srcIP, udp.SrcPort)),
			logfmt("dst", fmt.Sprintf("%s:%d", dstIP, udp.DstPort)),
			logfmt("mac", dhcp.ClientHWAddr.String()),
			logfmt("xid", fmt.Sprintf("0x%08x", dhcp.Xid)),
			logfmt("ciaddr", dhcp.ClientIP.String()),
			logfmt("yiaddr", dhcp.YourClientIP.String()),
		}

		if reqIP != "" {
			fields = append(fields, logfmt("requested_ip", reqIP))
		}
		if host != "" {
			fields = append(fields, logfmt("hostname", host))
		}

		// Add all DHCP options with opt_ prefix
		for _, opt := range dhcp.Options {
			// Skip options we've already logged separately
			if opt.Type == layers.DHCPOptMessageType || opt.Type == layers.DHCPOptHostname || opt.Type == layers.DHCPOptRequestIP {
				continue
			}
			if len(opt.Data) == 0 {
				continue
			}
			optName := fmt.Sprintf("opt_%d", opt.Type)
			optValue := formatDHCPOptionValue(opt)
			fields = append(fields, logfmt(optName, optValue))
		}

		fmt.Println(joinNonEmpty(fields))
	}
}

func joinNonEmpty(fields []string) string {
	out := ""
	for _, f := range fields {
		if f == "" {
			continue
		}
		if out == "" {
			out = f
		} else {
			out += " " + f
		}
	}
	return out
}
