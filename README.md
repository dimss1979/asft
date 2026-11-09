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

## Command-line options

```
asft <config_file>       Run the gateway or node using this configuration
asft -c <config_file>    Check the configuration and print link fingerprints
asft -g                  Generate a new random key and exit
```

`-c` derives the keys without opening the serial port or transferring files.
It prints one line per configured link: a short fingerprint and the peer label.

```
1a62bab27150946f node01
```

`-g` prints a random 256-bit key encoded in base64.

## Run

### 1. Generate keys

Two kinds of key are used:

* `network_id` — one per network, identical in every config file. It is a salt, not a secret.
* Link key — one per gateway–node link. It appears in exactly two files: the gateway's `node` line and that node's `gateway` line.

A gateway with three nodes needs four keys: one `network_id` and three link keys.
Generate each with:

```
./asft -g
```

Rules:

* The two ends of a link must use the same link key.
* All `node` lines in one gateway config must have different keys and different labels.
* `network_id` must differ from every link key.

The configuration is rejected if any of these is violated.

### 2. Write configuration files

Gateway (`gateway.conf`):

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

Node (`node01.conf`):

```
debug 1
mode node
network_id NETWORK_KEY
port /dev/ttyUSB1 1200
gateway gw NODE01_KEY
```

Replace the placeholders with keys from `./asft -g`. The placeholders are not valid keys and are rejected.

* `NETWORK_KEY` is the same in every file.
* `NODE01_KEY` is the same in the gateway's `node node01` line and in node01's `gateway` line.
* `NODE02_KEY` and `NODE03_KEY` are different keys, each used by its own node.

Ready-made templates are provided as `gateway.conf.example` and `node01.conf.example` (also `node02`, `node03`).
Copy one without the `.example` suffix and edit it. Real configuration files are ignored by git.

### 3. Verify each link

Run `-c` on both ends:

```
./asft -c gateway.conf
1a62bab27150946f node01

./asft -c node01.conf
1a62bab27150946f gw
```

The fingerprints must match, even though the labels differ.
A mismatch means the link key or `network_id` is different in the two files. Fix it before continuing.

### 4. Create directories

Directory names come from peer labels: `to_<label>` and `from_<label>`.
Create them in the working directory of `asft`.

On the gateway (for three nodes):

```
mkdir from_node01 from_node02 from_node03
mkdir to_node01 to_node02 to_node03
```

On each node:

```
mkdir from_gw to_gw
```

A file placed in the gateway's `to_node01` arrives in node01's `from_gw`.
A file placed in node01's `to_gw` arrives in the gateway's `from_node01`.

### 5. Start

Run on each host with its own configuration:

```
./asft gateway.conf
./asft node01.conf
```

Run it manually or under `systemd` or `procd`.
There is no daemonize option.

### Sending files

A file is picked up as soon as it appears under a normal name in a `to_<label>` directory.
To avoid sending a half-written file, choose one of these ways, best first:

1. **Best:** create a temporary file whose name begins with a dot (for example `.report.tmp`) in the `to_<label>` directory itself, write it, then rename it to the final name. Names beginning with a dot are ignored by `asft`, and a rename within one directory is atomic.
2. **Second best:** write the file in another directory, then move it into the `to_<label>` directory. Both directories must be on the same filesystem, otherwise the move is a copy and is not atomic.
3. **Not recommended:** write the file directly under its final name in the `to_<label>` directory. `asft` may pick it up before writing is finished, and only part of the file will be transferred.

* Symlinks are not transferred.
* Multiple files are sent in ascending `ctime` order: the file moved in first is sent first.

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

