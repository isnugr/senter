package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

type flowKey struct {
	AAddr string
	APort string
	BAddr string
	BPort string
	Proto string
}

type flowStats struct {
	AAddr string
	APort string
	BAddr string
	BPort string
	Proto string

	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
}

type snapshot struct {
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
	timestamp time.Time
}

type aggregator struct {
	sync.Mutex
	flows map[flowKey]*flowStats
}

func newAggregator() *aggregator {
	return &aggregator{flows: make(map[flowKey]*flowStats)}
}

func (a *aggregator) update(pkt gopacket.Packet) {
	network := pkt.NetworkLayer()
	transport := pkt.TransportLayer()
	if network == nil {
		return
	}

	var srcAddr, dstAddr string
	switch layer := network.(type) {
	case *layers.IPv4:
		srcAddr = layer.SrcIP.String()
		dstAddr = layer.DstIP.String()
	case *layers.IPv6:
		srcAddr = layer.SrcIP.String()
		dstAddr = layer.DstIP.String()
	default:
		return
	}

	proto := strings.ToLower(network.LayerType().String())
	var srcPort, dstPort string
	if transport != nil {
		switch layer := transport.(type) {
		case *layers.TCP:
			srcPort = layer.SrcPort.String()
			dstPort = layer.DstPort.String()
			proto = "tcp"
		case *layers.UDP:
			srcPort = layer.SrcPort.String()
			dstPort = layer.DstPort.String()
			proto = "udp"
		}
	}
	if proto == "ipv4" || proto == "ipv6" {
		if pkt.Layer(layers.LayerTypeICMPv4) != nil {
			proto = "icmp"
		} else if pkt.Layer(layers.LayerTypeICMPv6) != nil {
			proto = "icmpv6"
		}
	}

	forward := true
	aAddr := srcAddr
	aPort := srcPort
	bAddr := dstAddr
	bPort := dstPort

	if compareAddress(srcAddr, dstAddr) > 0 || (srcAddr == dstAddr && srcPort > dstPort) {
		forward = false
		aAddr, bAddr = dstAddr, srcAddr
		aPort, bPort = dstPort, srcPort
	}

	length := len(pkt.Data())
	if length <= 0 {
		return
	}

	key := flowKey{AAddr: aAddr, APort: aPort, BAddr: bAddr, BPort: bPort, Proto: proto}

	a.Lock()
	stats, ok := a.flows[key]
	if !ok {
		stats = &flowStats{AAddr: aAddr, APort: aPort, BAddr: bAddr, BPort: bPort, Proto: proto}
		a.flows[key] = stats
	}
	if forward {
		stats.txBytes += uint64(length)
		stats.txPackets++
	} else {
		stats.rxBytes += uint64(length)
		stats.rxPackets++
	}
	a.Unlock()
}

func (a *aggregator) snapshot() map[flowKey]flowStats {
	a.Lock()
	defer a.Unlock()

	copyMap := make(map[flowKey]flowStats, len(a.flows))
	for k, v := range a.flows {
		copyMap[k] = *v
	}
	return copyMap
}

func buildFilter(src, dst string, port int, proto string) string {
	var clauses []string
	if src != "" {
		clauses = append(clauses, fmt.Sprintf("src host %s", src))
	}
	if dst != "" {
		clauses = append(clauses, fmt.Sprintf("dst host %s", dst))
	}
	if port != 0 {
		clauses = append(clauses, fmt.Sprintf("port %d", port))
	}
	if proto != "" {
		normalized := strings.ToLower(proto)
		switch normalized {
		case "tcp", "udp", "icmp", "icmp6", "icmpv6", "ip", "arp":
			if normalized == "icmpv6" {
				normalized = "icmp6"
			}
			clauses = append(clauses, normalized)
		default:
			log.Printf("unknown protocol '%s' ignored", proto)
		}
	}
	return strings.Join(clauses, " and ")
}

func formatRate(bytesPerSecond float64) string {
	if bytesPerSecond <= 0 {
		return "0 B/s"
	}

	units := []string{"B/s", "KB/s", "MB/s", "GB/s", "TB/s"}
	i := 0
	for bytesPerSecond >= 1024 && i < len(units)-1 {
		bytesPerSecond /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", bytesPerSecond, units[i])
}

func formatPacketsPerSecond(pktPerSecond float64) string {
	if pktPerSecond <= 0 {
		return "0 pkt/s"
	}

	units := []string{"pkt/s", "kpkt/s", "Mpkt/s", "Gpkt/s"}
	i := 0
	for pktPerSecond >= 1000 && i < len(units)-1 {
		pktPerSecond /= 1000
		i++
	}
	return fmt.Sprintf("%.1f %s", pktPerSecond, units[i])
}

func compareAddress(a, b string) int {
	if a == b {
		return 0
	}

	// Attempt to parse as IP addresses to ensure consistent ordering
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)

	if ipA != nil && ipB != nil {
		return bytesCompare(ipA, ipB)
	}

	if ipA != nil {
		return -1
	}
	if ipB != nil {
		return 1
	}

	if a < b {
		return -1
	}
	return 1
}

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}

	if len(a) == len(b) {
		return 0
	}
	if len(a) < len(b) {
		return -1
	}
	return 1
}

func main() {
	iface := flag.String("iface", "", "Interface to monitor (required)")
	src := flag.String("src", "", "Source address filter")
	dst := flag.String("dst", "", "Destination address filter")
	port := flag.Int("port", 0, "Port filter")
	proto := flag.String("proto", "", "Protocol filter (tcp, udp, icmp, icmp6, ip, arp)")
	refresh := flag.Duration("refresh", time.Second, "UI refresh interval")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "interface is required")
		flag.Usage()
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to open interface %s: %v", *iface, err)
	}
	defer handle.Close()

	filter := buildFilter(*src, *dst, *port, *proto)
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("failed to set BPF filter: %v", err)
		}
	}

	agg := newAggregator()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	errChan := make(chan error, 1)

	go func() {
		for pkt := range packetSource.Packets() {
			agg.update(pkt)
		}
		errChan <- errors.New("packet source closed")
	}()

	app := tview.NewApplication()
	table := tview.NewTable().SetBorders(true)
	table.SetFixed(1, 0)
	table.SetSelectable(true, false)
	setTableHeaders(table)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'q', 'Q':
				app.Stop()
				return nil
			}
		}
		if event.Key() == tcell.KeyEscape {
			app.Stop()
			return nil
		}
		return event
	})

	last := make(map[flowKey]snapshot)

	ticker := time.NewTicker(*refresh)
	defer ticker.Stop()
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				stats := agg.snapshot()
				now := time.Now()
				rows := buildRows(stats, last, now, *refresh)
				last = updateSnapshots(stats, now)

				app.QueueUpdateDraw(func() {
					updateTable(table, rows)
				})
			case <-done:
				return
			}
		}
	}()

	err = app.SetRoot(table, true).EnableMouse(false).Run()
	if err != nil {
		log.Fatalf("ui error: %v", err)
	}
	close(done)

	select {
	case err = <-errChan:
		if err != nil {
			log.Printf("capture stopped: %v", err)
		}
	default:
	}
}

func setTableHeaders(table *tview.Table) {
	headers := []string{"SRC", "SPORT", "DST", "DPORT", "PROTO", "TX RATE", "RX RATE", "TX PPS", "RX PPS", "TX PKTS", "RX PKTS"}
	for i, h := range headers {
		table.SetCell(0, i, tview.NewTableCell(h).SetAttributes(tcell.AttrBold))
	}
}

type row struct {
	src       string
	sport     string
	dst       string
	dport     string
	proto     string
	txRate    string
	rxRate    string
	txPPS     string
	rxPPS     string
	txPackets uint64
	rxPackets uint64
	orderKey  float64
}

func buildRows(stats map[flowKey]flowStats, last map[flowKey]snapshot, now time.Time, interval time.Duration) []row {
	rows := make([]row, 0, len(stats))
	for key, val := range stats {
		prev, ok := last[key]
		deltaTime := interval.Seconds()
		if ok {
			delta := now.Sub(prev.timestamp).Seconds()
			if delta > 0 {
				deltaTime = delta
			}
		}

		txBytesDelta := float64(val.txBytes - prev.txBytes)
		rxBytesDelta := float64(val.rxBytes - prev.rxBytes)
		txPacketsDelta := float64(val.txPackets - prev.txPackets)
		rxPacketsDelta := float64(val.rxPackets - prev.rxPackets)

		txRate := txBytesDelta / deltaTime
		rxRate := rxBytesDelta / deltaTime
		txPPS := txPacketsDelta / deltaTime
		rxPPS := rxPacketsDelta / deltaTime

		rows = append(rows, row{
			src:       val.AAddr,
			sport:     val.APort,
			dst:       val.BAddr,
			dport:     val.BPort,
			proto:     strings.ToUpper(val.Proto),
			txRate:    formatRate(txRate),
			rxRate:    formatRate(rxRate),
			txPPS:     formatPacketsPerSecond(txPPS),
			rxPPS:     formatPacketsPerSecond(rxPPS),
			txPackets: val.txPackets,
			rxPackets: val.rxPackets,
			orderKey:  txRate + rxRate,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].orderKey > rows[j].orderKey
	})

	return rows
}

func updateSnapshots(stats map[flowKey]flowStats, now time.Time) map[flowKey]snapshot {
	snaps := make(map[flowKey]snapshot, len(stats))
	for key, val := range stats {
		snaps[key] = snapshot{
			txBytes:   val.txBytes,
			rxBytes:   val.rxBytes,
			txPackets: val.txPackets,
			rxPackets: val.rxPackets,
			timestamp: now,
		}
	}
	return snaps
}

func updateTable(table *tview.Table, rows []row) {
	for i := table.GetRowCount() - 1; i >= 1; i-- {
		table.RemoveRow(i)
	}

	for i, r := range rows {
		rowIndex := i + 1
		table.SetCell(rowIndex, 0, tview.NewTableCell(r.src))
		table.SetCell(rowIndex, 1, tview.NewTableCell(r.sport))
		table.SetCell(rowIndex, 2, tview.NewTableCell(r.dst))
		table.SetCell(rowIndex, 3, tview.NewTableCell(r.dport))
		table.SetCell(rowIndex, 4, tview.NewTableCell(r.proto))
		table.SetCell(rowIndex, 5, tview.NewTableCell(r.txRate))
		table.SetCell(rowIndex, 6, tview.NewTableCell(r.rxRate))
		table.SetCell(rowIndex, 7, tview.NewTableCell(r.txPPS))
		table.SetCell(rowIndex, 8, tview.NewTableCell(r.rxPPS))
		table.SetCell(rowIndex, 9, tview.NewTableCell(fmt.Sprintf("%d", r.txPackets)))
		table.SetCell(rowIndex, 10, tview.NewTableCell(fmt.Sprintf("%d", r.rxPackets)))
	}
}
