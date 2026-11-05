# Automated Serial File Transfer tool

A modern replacement for XMODEM and UUCP.

Exchange files where TCP/IP just can't.

## Introduction

This software enables secure, unattended, multipoint, bidirectional file transfer over a severely constrained channel.
Two or more Linux hosts exchange files automatically over a serial port.
A wide range of transmission speeds and line types is supported.

Minimum line requirements are:

* 8 bits (8N1)
* Half-duplex (full-duplex is also supported)
* Default frame size is 110 bytes

Examples:

* RS-485
* RS-232
* UART
* SHDSL modem
* LoRa serial modem
* other wireless and wired modems

The star-shaped network consists of a single gateway and one or more nodes.
The communication is always initiated by the gateway.
Nodes only respond to requests coming from the gateway.

Default file size limit is 1000000 bytes.
Files whose names begin with a dot are never sent and are rejected on receipt. Names containing `/`, `\` or control characters are also skipped.
Only readable regular files are sent. Symlinks are ignored.

## Build

```
./build.sh
```

Adjust build script as needed.
OpenSSL 3.x is required.

## Command-line Options

`asft` accepts the following command-line options:

* `<config_file>` — Run the gateway or node operation loop using the specified configuration file.
* `-c <config_file>` — Verify the configuration without opening the serial port or starting file transfer. It derives the keys and prints one line per configured link: a short fingerprint followed by the peer label:
  ```
  1a62bab27150946f node01
  ```
  Run it on both ends of a link and compare the fingerprint for that link. The gateway's `node` line and the node's `gateway` line must print the same fingerprint, even though their labels differ. A mismatch means the two configurations do not contain the same link key, or their `network_id` values differ.
* `-g` — Generate and print a new random 256-bit base64-encoded key, then exit.

## Run

First, create a configuration file on each host.
Every key is a random 256-bit value encoded in base64.
Two different kinds of key are used, and they are not interchangeable:

| Value | Where it appears | How many |
| --- | --- | --- |
| `network_id` | one `network_id` line in the gateway config and in every node config | one per network, identical everywhere |
| Link key for `node01` | gateway: `node node01 <key>`; node01: `gateway <label> <key>` | one per gateway–node link, written in exactly those two files |

`network_id` is a salt, not a secret.
A link key is the key shared by the two ends of one gateway–node link: the gateway and that node necessarily use the same key for that link.
It is not a separate "gateway key".
A gateway with three nodes has three link keys, and each node configuration contains only the key for its own link.

Uniqueness is per link: all `node` lines in one gateway configuration must have different keys (and different labels).
The configuration is rejected if two `node` lines share a key or a label, or if `network_id` equals any peer key.
Sharing a key between the two ends of the same link is required, not an error.

Generate one key per link plus one for `network_id`.
`-g` prints a new random key and exits, similar to `wg genpsk`:

```
./asft -g
```

For a gateway with three nodes, run it four times: once for `network_id` and once for each of node01, node02 and node03.
Keep track of which key belongs to which node.

Sample configuration file for gateway (`gateway.conf`):

```
debug 1
mode gateway
network_id NETWORK_KEY
port /dev/ttyUSB0 1200
retry_timeout 2
backoff_time_max 60

node node01 NODE01_KEY
#node node02 NODE02_KEY
#node node03 NODE03_KEY
```

Sample configuration file for node01 (`node01.conf`):

```
debug 1
mode node
network_id NETWORK_KEY
port /dev/ttyUSB1 1200
gateway gw NODE01_KEY
```

`NETWORK_KEY` is the same value in every configuration file.
`NODE01_KEY` is the same value in the gateway's `node node01` line and in node01's `gateway` line.
`NODE02_KEY` and `NODE03_KEY` are different values, each used by its own node.

The placeholders are not valid keys and the configuration parser rejects them.
Replace each one with output of `./asft -g`.
Do not copy the same generated key into several `node` lines.

Check every link before starting the transfer.
`-c` validates the configuration and prints one fingerprint per configured link.
On the gateway:

```
./asft -c gateway.conf
```
```
1a62bab27150946f node01
```

On node01:

```
./asft -c node01.conf
```
```
1a62bab27150946f gw
```

The gateway's `node01` fingerprint must equal the fingerprint printed on node01, even though the labels differ (`node01` versus `gw`).
That equality proves that the two files contain the same link key and the same `network_id`.
If the fingerprints differ, fix the key or `network_id` before running `asft`.

Next, run `asft` on each host with its own configuration file:

```
./asft gateway.conf
./asft node01.conf
```

You can run it manually or under supervision of `systemd` or `procd` if you wish.
Note that there is no option to daemonize the process - this is not required these days.

Sample configuration files are provided as `gateway.conf.example` and `node01.conf.example` (and `node02`, `node03`). They are examples only. Copy one to a file without the `.example` suffix and edit it. The real configuration files are ignored by git.

You need to create directories for incoming and outgoing files. At the gateway:

```
from_node01
from_node02
from_node03
to_node01
to_node02
to_node03
```

At each node:

```
from_gw
to_gw
```

Directory names are derived from node labels.
Files are picked from the corresponding `to_node_label` directory of the gateway, transferred to that node, and placed in its `from_gw` directory.
In the opposite direction, files travel from `to_gw` to `from_node_label` directory.

The user is advised to write their data to a temporary file in another directory.
Files whose names begin with a dot are ignored by `asft`.
The same `to_label` directory can be used if your temporary file name begins with a dot.
Then move/rename the file into the `to_label` directory.
The file is ready for transfer.
Symlinks in the `to_label` directory are not transferred, so do not use them.

When multiple files are available, they are transferred in ascending `ctime` order.
In other words, the regular file moved first into the `to_label` directory is transferred first.

## Gateway operation

Gateway is the initiator of all packet exchange.
It polls its nodes in a round-robin manner.

There are two packet types:

1. Long packets carrying file fragments and flags
2. Short packets carrying only flags

## Node operation

The node only responds to gateway requests.
It never initiates communication.

## File transfer

`asft` is based on a sequential, bidirectional file transfer protocol.

The context of file transfer is preserved across connectivity loss.
File transfer will resume when connectivity is restored as long as you keep the `asft` process running at both ends.
This is very helpful with slow communication channels.

## Configuration options

### debug

Set to '1' for more verbose logging.

### mode

Either 'gateway' or 'node'.

### network_id

Base64 encoded 256-bit salt for key derivation. This option is mandatory.
It is used as the HKDF salt.

It must be identical on the gateway and every node. Generate it with:

```
./asft -g
```

`network_id` is not a secret, but it should be unique to your network. It
prevents identical peer keys on different networks from producing the same
derived keys. The value must be a valid base64-encoded 256-bit key (exactly 44 characters, with no whitespace).

Config parsing validates that `network_id` conforms to this format and fails to start if invalid.

Changing `network_id` changes all derived keys, so update all peers together.

`network_id` must differ from every peer key. The configuration is rejected otherwise.

### port

Serial port device and baudrate.

Default USB serial port name in Linux is in the form:

```
/dev/ttyUSB0
/dev/ttyUSB1
/dev/ttyUSB2
...
```

When multiple USB serial ports are connected to the same computer, their numbering order is not guaranteed.
Debian and probably some other Linux distributions provide an alternative naming scheme based on USB device serial number.
For example, if the USB serial port number is "ABCD1234":

```
/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_ABCD1234-if00-port0
```

You should use these if available in your system.
Also, make sure the serial port is accessible.
In Debian, the user must be a member of the "dialout" group.

### retry_timeout

(gateway only) Wait for a response for the specified amount of seconds.

If exceeded, the packet will be retransmitted.

### backoff_time_max

(gateway only) Maximum backoff time in seconds (default: 60).

When a node does not respond or there is no data to transfer, the gateway will pause that node using exponential backoff:
- Initial pause is 1 second
- Each subsequent timeout doubles the pause time (2s, 4s, 8s, etc.)
- Maximum pause time is limited by `backoff_time_max`
- When a response is received and there is data to transfer, the backoff is reset to zero
- When a "error while processing data packet" condition occurs, either on the gateway or on the node, the backoff is set to half of `backoff_time_max`. The node signals its own error to the gateway with the `err` flag in its response

### timestamp_step

Timestamp step in milliseconds (default: 1).

This parameter controls the granularity of timestamps used as nonces for packet encryption.
Increasing this value is useful in two cases:

- When the communication channel is extra slow
- When you want to allow a larger clock offset

By default, maximum permissible sum of data packet transmission time and clock offset is ~32.8 seconds.

Timestamp step must be smaller than data packet transmission time.
Otherwise, some packets will fail to decrypt.

### serial_packet_loss

Packet loss probability in serial frame receive path (default: 0.0).

This parameter accepts values from 0.0 to 1.0 and controls the probability of dropping received frames before they are reported to the caller.
A value of 0.0 means no packet loss (default), while 1.0 means all packets are dropped.

This option is for testing purposes only, to simulate unreliable communication channels.

### node

(gateway only) Label and base64 256-bit link key for a peer node.

This key must be the same as the key on the `gateway` line in that node's configuration. It is the key for this gateway–node link only; every `node` line on the gateway must use a different key.

The key must be a valid 256-bit key generated with `./asft -g` (exactly 44 base64 characters). Config parsing validates the key format on startup.

Label is used for:

* derivation of incoming and outgoing directory names
* log messages corresponding to particular node

You must use unique labels to prevent confusion. The configuration is rejected if two nodes share a label.

Directory names follow the pattern: `to_label` and `from_label`.
Both directories must be created in advance in the working directory of `asft`.

You can specify multiple nodes for multipoint operation if transmission medium permits.

### gateway

(node only) Label and base64 256-bit link key for the gateway.

This key must be the same as the key on the gateway's `node` line for this node. It is the key for this gateway–node link only; it is not a key shared by all nodes.

The key must be a valid 256-bit key generated with `./asft -g` (exactly 44 base64 characters). Config parsing validates the key format on startup.

Label is used for:

* derivation of incoming and outgoing directory names

Directory names follow the pattern: `to_label` and `from_label`.
Both directories must be created in advance in the working directory of `asft`.

## Security

Each node is addressed by its key only.
Use keys generated with `./asft -g` and never reuse them.
Protect `asft` configuration files, since they contain the keys.

Each peer key is the input keying material for HKDF, and `network_id` is the
HKDF salt. It is not a secret, but it must be identical on all peers and unique
to the network.

Time must be kept in sync between the gateway and all nodes by whatever means (for example NTP, chrony, GPS, or a manually set and well-maintained RTC). `asft` does not synchronize clocks itself. Clocks must agree within a few seconds, otherwise packets cannot be decrypted.

Each transmitted packet is encrypted and authenticated.
Each file is additionally authenticated. File authentication keys are separate for each direction, so a file cannot be reflected back to its sender.
Basic encryption, authentication, and replay protection are implemented.
Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS) are not currently implemented.
Only symmetric encryption is used.

### Packet encryption

Packets use chaSIV, a committing, misuse-resistant AE transform built from a hash function, a PRF, and a stream cipher (ChaCha20). It is defined in Chen and Karadžić, [*Committing Authenticated Encryption: Generic Transforms with Hash Functions*](https://eprint.iacr.org/2025/320) (EUROCRYPT 2025), Section 4.2. The exact instantiation is documented in `asft_crypto.c`.

### Known trade-offs

* **Short packet tag.** Each packet carries a 40-bit authentication tag, chosen to keep per-packet overhead low on slow links. An attacker who can inject packets has about a 2^-40 chance per attempt of forging one. The same tag also serves as the encryption nonce. The file header and body MACs are longer and are the end-to-end integrity check.
* **Replay protection depends on the clock.** Each side starts its replay high-water mark from the system clock when `asft` starts, and does not store it. If a node's clock is set backwards across a restart, previously captured requests may be accepted again. Keep clocks monotonic, for example with a working RTC or NTP, and do not restore an old clock value after a restart.

