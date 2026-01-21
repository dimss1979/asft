# Automated Serial File Transfer tool

This software is intended for a reliable, secure, unattended, multipoint file transfer over a serial line.
Two or more Linux hosts can exchange files automatically over a serial line.
A wide range of transmission speeds and line types is supported.
Minimum line requirements are:

* 8 bits (8N1)
* Half-duplex. Full duplex is supported as well.
* By default, maximum frame size is 112 bytes.

Examples:

* RS-485
* RS-232
* UART
* SHDSL modem
* LoRa serial modem
* other wireless and wired modems
* _et cetera_

The network consists of a single gateway and one or more nodes.
The communication is always initiated by the gateway.
Nodes only respond to requests coming from gateway.
Half-duplex nature and security make `asft` different from many other serial file transfer protocols.

COBS framing is used.
With default block and header size, maximum frame size is 112 bytes (including start and stop delimiters).

By default, `asft` will transfer files with size up to 1000000 bytes.
File names beginning with a dot are ignored.
Symlinks are allowed.
Other files are ignored.

## Build

```
./build.sh
```

Adjust build script as needed.
OpenSSL 3.x is required.

## Run

First of all, create configuration file.
You better use long and random passwords.

**Each peer must have a unique password.**

Next, run `asft`.

You can run it manually or under supervision of `systemd` or `procd` if you wish.
Note that there is no option to daemonize process - this is not required these days.

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

You need to create yourself directories for incoming and outgoing files. At the gateway:

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
The program will pick files from corresponding `to_node_label` directory of the gateway, transfer them to that node and place in its `from_gateway_label` directory.
This is called "download".
The opposite process of file transfer from node to gateway is called "upload".

The user is advised to write their data to some temporary file in another directory.
Dotfiles are ignored by `asft`.
The same `to_label` directory can be used if your temporary file name is beginning with a dot.
And then move/rename file or create a symlink in `to_label` directory.
The file is ready for transfer.

When multiple files are available, they are transferred in ascending "ctime" order.
In other words, the file moved first or symlink created first in `to_label` directory is transferred first.

## Gateway operation

Gateway is the initiator of all packet exchange.
It will interleave packets intended for all configured nodes in round robin manner.

There are two packet types:

1. Long packets carrying file fragments and ACKs
2. Short packets carrying only ACKs

## Node operation

The node only responds to gateway requests.
It never initiates communication.

## File transfer

`asft` is based on a sequential, bidirectional file transfer protocol.

The context of file transfer is preserved across timeouts.
File transfer will resume after timeout as long as you keep "asft" process running at both ends.
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
Debian and probably some other Linux distributions are providing an alternative naming scheme based on USB device serial number.
For example, USB serial port number is "ABCD1234":

```
/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_ABCD1234-if00-port0
```

You better use these if available in your system.
Also, make sure serial port is accessible.
In Debian, the user must be a member of "dialout" group.

### retry_timeout

(gateway only) Wait for response for specified amount of seconds.

If exceeded, the packet will be retransmitted.

### backoff_time_max

(gateway only) Maximum backoff time in seconds (default: 60).

When a node does not respond or there is no data to transfer, the gateway will pause that node using exponential backoff:
- Initial pause is 1 second
- Each subsequent timeout doubles the pause time (2s, 4s, 8s, etc.)
- Maximum pause time is limited by `backoff_time_max`
- When a response is received and there is a data to transfer, the backoff is reset to zero

### node

(gateway only) Label and password for a peer node.

Label is used for:

* derivation of incoming and outgoing directory names
* log messages corresponding to particular node

You have to use unique labels to prevent confusion.

Directory names are in the form: `to_label`, `from_label`.
Both directories must be created in advance in the working directory of `asft`.

You can specify multiple nodes for multipoint operation if transmission medium permits.

### gateway

(node only) Label and password for the gateway.

Label is used for:

* derivation of incoming and outgoing directory names

Directory names are in the form: `to_label`, `from_label`.
Both directories must be created in advance in the working directory of `asft`.

## Security

Each node is addressed by its password only.
Each transmitted packet is encrypted and authenticated.
Only basic encryption, authentication and replay protection is implemented.
No PFS, no PCS at the moment.
Gateway and node must maintain clock synchronization within a few seconds.

Only symmetric encryption is used.
Should have some quantum computer attack resistance.
