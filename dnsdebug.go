package main

// Optional DNS trace (opt-in: GATEWAY_DEBUG_DNS=1).
//
// The regular frame log shows Ethernet MACs only, which cannot tell
// "the guest asked 192.168.4.1" from "the guest asked 8.8.8.8" (both
// egress through the gateway MAC). This tracer prints the IP/port level
// detail of every DNS message that crosses the hub, in both directions:
// guest -> gateway (query) and gateway -> guest (answer).
//
// It is a diagnostic aid only: nothing here changes packet handling, and
// with the env var unset the code path is a single boolean check.

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

var (
	dnsDebugOnce sync.Once
	dnsDebugOn   bool
)

func dnsDebugEnabled() bool {
	dnsDebugOnce.Do(func() {
		v := strings.TrimSpace(strings.ToLower(os.Getenv("GATEWAY_DEBUG_DNS")))
		dnsDebugOn = v != "" && v != "0" && v != "false" && v != "no"
	})
	return dnsDebugOn
}

// logDNSFrame prints one DNS message (query or response) with the
// IP/port level detail the MAC-only frame log hides.
func logDNSFrame(dir string, frame []byte) {
	if !dnsDebugEnabled() {
		return
	}
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if ipLayer == nil || udpLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	udp, _ := udpLayer.(*layers.UDP)
	if udp.DstPort != 53 && udp.SrcPort != 53 {
		return
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(udp.Payload); err != nil {
		fmt.Printf("[DNS] %s %s:%d -> %s:%d (unparsable DNS payload, %d bytes)\n",
			dir, ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort, len(udp.Payload))
		return
	}
	qname := ""
	qtype := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
		qtype = dns.TypeToString[msg.Question[0].Qtype]
	}
	answers := []string{}
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			answers = append(answers, "A "+v.A.String())
		case *dns.AAAA:
			answers = append(answers, "AAAA "+v.AAAA.String())
		case *dns.CNAME:
			answers = append(answers, "CNAME "+v.Target)
		default:
			answers = append(answers, strings.TrimSpace(rr.String()))
		}
	}
	fmt.Printf("[DNS] %s %s:%d -> %s:%d id=%d q=%q type=%s rcode=%s answers=%v\n",
		dir, ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort,
		msg.Id, qname, qtype, dns.RcodeToString[msg.Rcode], answers)
}
