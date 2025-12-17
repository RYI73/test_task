# ESP32 SPI L3 Forwarder – Architecture and Protocol

## Overview

This project implements a **Layer-3 (IPv4) packet forwarder** between:

* **Wi-Fi STA interface on ESP32 (via lwIP)**
* **SPI link to a Raspberry Pi**

The ESP32 does **not** act as a TCP/IP endpoint or router. Instead, it behaves like a **smart network interface (L3 bridge)** that forwards raw IPv4 packets between Wi-Fi and SPI using a lightweight custom framing protocol.

The Raspberry Pi terminates the SPI link and injects/extracts packets into/from a **TUN interface**, allowing the Linux kernel to handle routing, TCP, UDP, and applications.

---

## High-Level Data Flow

```
        ┌──────────────┐        SPI (framed IPv4)       ┌──────────────┐
        │              │  <-------------------------->  │              │
        │   ESP32      │                                │ Raspberry Pi │
        │              │                                │              │
        │  Wi-Fi STA   │                                │   SPI Master │
        │     +        │                                │     +        │
        │   lwIP RAW   │                                │    TUN       │
        │              │                                │              │
        └──────┬───────┘                                └──────┬───────┘
               │                                               │
               ▼                                               ▼
          Wi-Fi Network                                  Linux IP Stack
```

---

## Role of ESP32

The ESP32 is responsible for:

1. Connecting to a Wi-Fi network in **STA mode**
2. Receiving **raw IPv4 packets** from Wi-Fi using **lwIP RAW PCB**
3. Forwarding those packets to Raspberry Pi over **SPI**
4. Receiving IPv4 packets from Raspberry Pi over SPI
5. Injecting received packets back into lwIP for transmission over Wi-Fi

### Restrictions of ESP32

* No TCP or UDP processing
* No routing table or forwarding decisions
* No ARP/DHCP logic (handled by lwIP internally)
* No packet segmentation or reassembly

ESP32 forwards packets **blindly**, without inspecting destination IP addresses.

---

## Why lwIP is Used

lwIP is used **only as an IP ingress/egress interface for Wi-Fi**:

* To receive IPv4 packets from the Wi-Fi driver
* To transmit IPv4 packets back to the Wi-Fi driver

lwIP is **not** used as a transport stack (TCP/UDP sockets are not used).

The RAW PCB API is the only **stable, public, and supported** way in ESP-IDF to intercept and inject IP packets.

---

## SPI Packet Framing Protocol

IPv4 packets are encapsulated into a simple SPI frame to ensure:

* Packet boundary detection
* Versioning
* Integrity verification (CRC32)

### SPI Frame Layout

```
+------------+---------+-------+----------+-------------+----------+
|  Magic     | Version | Flags |  Length  |   Payload   |  CRC32   |
+------------+---------+-------+----------+-------------+----------+
|  4 bytes   | 1 byte  | 1 b   | 2 bytes  | N bytes     | 4 bytes  |
+------------+---------+-------+----------+-------------+----------+
```

### Header Definition

```c
uint32_t magic;     // Magic constant SPI_MAGIC ('IPFW')
uint8_t  version;   // Protocol version (0x01)
uint8_t  flags;     // Reserved for future use
uint16_t length;    // IPv4 packet length in bytes
```

### Field Description

| Field   | Description                                                     |
| ------- | --------------------------------------------------------------- |
| magic   | Fixed value `0x49504657` (`'IPFW'`) to validate frame alignment |
| version | Protocol version (currently `1`)                                |
| flags   | Reserved for future extensions (segmentation, QoS, etc.)        |
| length  | Length of IPv4 payload in bytes                                 |
| payload | Raw IPv4 packet (no Ethernet header)                            |
| CRC32   | CRC32 over payload only                                         |

---

## SPI Transmission Rules

* One SPI frame = one IPv4 packet
* Maximum payload size is limited by `SPI_MTU`
* No fragmentation or reassembly is implemented
* Frames with invalid magic, version, length, or CRC are dropped

---

## Raspberry Pi Responsibilities

On the Raspberry Pi side:

1. SPI operates in **master mode**
2. Received SPI frames are:
    * Validated (magic, version, length, CRC)
    * Payload extracted (raw IPv4 packet)
3. Extracted IPv4 packets are written into a **TUN interface**
4. Linux kernel processes packets normally:
    * Routing
    * TCP/UDP handling
    * Applications (client/server)

### Reverse Direction (Pi -> ESP32)

1. Linux writes IPv4 packets to the TUN interface
2. Userspace program reads packets from TUN
3. Packets are wrapped into SPI frames
4. Frames are sent over SPI to ESP32
5. ESP32 injects packets into lwIP -> Wi-Fi

---

## Design Implications

* The Raspberry Pi acts as the **real network node**
* ESP32 acts as a **Wi-Fi IP front-end**
* The SPI link is effectively a **virtual L3 cable**

This design allows:

* Using standard Linux networking tools
* Running unmodified TCP/IP applications
* Avoiding TCP/IP implementation on ESP32

---

## Limitations

* SPI_MTU must be >= maximum IPv4 packet size
* No segmentation -> packets larger than SPI_MTU are dropped
* Latency depends on SPI clock and transaction size

---

## Possible Extensions

* Packet segmentation and reassembly
* Flow control / credits
* Multiple virtual links
* IPv6 support
* Encryption/authentication on SPI

---

## Summary

ESP32 forwards raw IPv4 packets between Wi-Fi and SPI using lwIP RAW PCB and a simple framed SPI protocol. The Raspberry Pi terminates the link using a TUN interface and handles all higher-level networking logic using the Linux kernel.
