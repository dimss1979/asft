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
File names beginning with a dot are ignored.
Symlinks are allowed.

## Build

```
./build.sh
```

Adjust build script as needed.
OpenSSL 3.x is required.

## Run

First, create a configuration file.
You should use long and random passwords.

**Each peer must have a unique password.**

Next, run `asft`.

You can run it manually or under supervision of `systemd` or `procd` if you wish.
Note that there is no option to daemonize the process - this is not required these days.

```
./asft configuration_file.conf
```

Sample configuration file for gateway:

```
debug 1
mode gateway
port /dev/ttyUSB0 1200
retry_timeout 2
backoff_time_max 60

node node01 password123
#node node02 password234
#node node03 password345
```

Sample configuration file for node01:

```
debug 1
mode node
port /dev/ttyUSB1 1200
gateway gw password123
```

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
Dotfiles are ignored by `asft`.
The same `to_label` directory can be used if your temporary file name begins with a dot.
Then move/rename the file or create a link in the `to_label` directory.
The file is ready for transfer.

When multiple files are available, they are transferred in ascending `ctime` order.
In other words, the file moved first or link created first in the `to_label` directory is transferred first.

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

(gateway only) Label and password for a peer node.

Label is used for:

* derivation of incoming and outgoing directory names
* log messages corresponding to particular node

You must use unique labels to prevent confusion.

Directory names follow the pattern: `to_label` and `from_label`.
Both directories must be created in advance in the working directory of `asft`.

You can specify multiple nodes for multipoint operation if transmission medium permits.

### gateway

(node only) Label and password for the gateway.

Label is used for:

* derivation of incoming and outgoing directory names

Directory names follow the pattern: `to_label` and `from_label`.
Both directories must be created in advance in the working directory of `asft`.

## Security

Each node is addressed by its password only.
Please use long, unique, hard to guess passwords.
Protect `asft` configuration files.

By default, gateway and nodes must maintain clock synchronization within a few seconds.

Each transmitted packet is encrypted and authenticated.
Each file is additionally authenticated.
Basic encryption, authentication, and replay protection are implemented.
Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS) are not currently implemented.
Only symmetric encryption is used.
