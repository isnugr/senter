# senter

`senter` is a terminal-based traffic torch for Linux interfaces written in Go. It captures live packets with [`gopacket`](https://github.com/google/gopacket) and renders a real-time table using [`tview`](https://github.com/rivo/tview).

## Features

- Real-time per-flow aggregation of transmit and receive byte/packet counts.
- Calculated TX/RX throughput (bytes per second) and packets per second.
- Filter capture traffic with optional source, destination, port, and protocol filters.
- Keyboard shortcuts (`q`, `Q`, or `Esc`) to exit the UI.

## Prerequisites

- Linux with libpcap installed (e.g. `sudo apt install libpcap-dev`).
- Root privileges or sufficient capabilities to capture packets on the chosen interface.

## Building

```bash
go build
```

## Running

```bash
sudo ./senter -iface eth0 -refresh 1s -proto tcp
```

### Available flags

| Flag | Description |
|------|-------------|
| `-iface` | **Required.** Network interface to capture from. |
| `-src` | Optional source IP filter. |
| `-dst` | Optional destination IP filter. |
| `-port` | Optional TCP/UDP port filter. |
| `-proto` | Optional protocol filter (`tcp`, `udp`, `icmp`, `icmp6`, `ip`, `arp`). |
| `-refresh` | UI refresh interval (default `1s`). |

All provided filters are combined into a single BPF expression before starting the capture.

## Controls

- `q`, `Q`, or `Esc` — quit the application.
- Arrow keys/Page Up/Page Down — navigate rows in the table.

## Notes

- Rates are derived from the change in counters between refresh intervals.
- Flows are normalized so that traffic between two endpoints is aggregated regardless of packet direction; the TX column is relative to the lexicographically smaller endpoint.
