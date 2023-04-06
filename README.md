# Automated Serial File Transfer tool

This software is intended for a reliable, secure, unattended, multipoint file transfer over a serial line.
Two or more Linux hosts can exchange files automatically over a serial line.
A wide range of transmission speeds and line types is supported.
Minimum line requirements are:

* 8 bits (8N1)
* Half-duplex. Full duplex is supported as well.
* By default, maximum frame size is 222 bytes. Can be reduced if needed.

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
With default block and header size, maximum frame size is 222 bytes (including start and stop delimiters).

By default, `asft` will transfer files with size up to 4294967295 bytes and filename up to 200 bytes.
File names beginning with a dot are ignored.
Symlinks are allowed.
Other files are ignored.

## Build

It does not have Makefile yet.

```
gcc -o asft -Wall -Werror -std=gnu11 *.c -lcrypto
```

or

```
clang -o asft -Wall -Werror -std=gnu11 *.c -lcrypto
```

OpenSSL 3.x is required.

## Run

You can run it manually or under supervision of `systemd` or `procd` if you wish.
Note that there is no option to daemonize process - this is not required these days.

```
./asft configuration_file.conf
```

Sample configuration files for gateway and nodes are included. You need to create yourself directories for incoming and outgoing files. At the gateway:

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
Note that dotfiles are ignored by `asft`.
The same `to_label` directory can be used if your temporary file name is beginning with a dot.
And then move/rename file or create a symlink in `to_label` directory.
The file is ready for transfer.

## Gateway operation

The gateway performs the following operations for each configured node in a loop:

1. Session key exchange
2. Try to upload a single file
3. Try to download a single file
4. If some file was actually transferred, repeat step 2
5. Stay idle until timeout expires or there is a file to download
6. Repeat step 2

When there are multiple files available, the node will spend most time in states 2-3.
When there are no files and no errors, the node will mostly stay in state 5.

Upon any error, the node is moved to a special error state.
After a specified amount of time, it will proceed to step 1 - session key exchange.

The gateway will interleave packets intended for all configured nodes in round robin manner.

## Node operation

The node only responds to gateway requests.
It never initiates communication.

## Configuration options

### debug

Set to '1' for more verbose logging.

### mode

Either 'gateway' or 'node'.

### network

Unique arbitrary string to be used as network name.
Must be the same on gateway and all its nodes.

This option prevents unexpected communication between hosts of different networks if their transmission medium is the same and they use the same password by coincidence.

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

### retries

(gateway only) Packet transmission maximum retry count.

If exceeded, the node is moved to error state.

### retry_timeout

(gateway only) Wait for response for specified amount of seconds.

If exceeded, the packet will be retransmitted.

### pause_idle

(gateway only) Stay in idle state for specified amount of seconds.

When there are no files to be trasferred, the node is moved to idle state.
The node leaves idle state and proceeds to upload when idle time is over or there is a file available for download.
Note that the gateway cannot detect if the node has a new file for upload while it's idle.

### pause_error

(gateway only) Stay in error state for specified amount of seconds.

The node is moved to error state upon any error.
When this time is over, the node will proceed to session key exchange.

### node

(gateway only) Label and password for node.

Label is used for:

* derivation of incoming and outgoing directory names
* log messages corresponding to particular node

So you better use unique labels to prevent confusion.

Directory names are in the form: `to_label`, `from_label`.
Both directories must be created in advance in the working directory of `asft`.

Password is used to derive an initial encryption key for the node.
As there is no other means to address particular node, its password *must* be unique.
You're advised to use long and hard to guess passwords.

You can specify multiple nodes for multipoint operation if transmission medium permits.

### gateway

(node only) Label and password for gateway.

Label is used for derivation of incoming and outgoing directory names.

Directory names are in the form: `to_label`, `from_label`.
Both directories must be created in advance in the working directory of `asft`.

Password must be configured the same on gateway and corresponding node.
As there is no other means to address particular node, its password *must* be unique.
You're advised to use long and hard to guess passwords.

## Security

Each node is addressed by its password.
Also, all nodes share common network name.

Initial encryption key is derived from network name and node password using "scrypt" function.
Session key is derived using "X25519" elliptic curve Diffie-Hellman algorithm followed by "sha3-256".

Each encryption key consists of two parts: inner and outer key. Inner key is derived as described above. Outer key is "sha3-256" of inner key.

Each packet is encryted and authenticated using "chacha20-poly1305" and inner key.
Packet number is used as initialization vector.
To randomize packet contents even further, packet number (initialization vector) is additionally encrypted using "chacha20" and outer key.
Authentication tag produced by "chacha20-poly1305" is used as initialization vector for "chacha20".

During session key exchange, packets are encrypted using initial key derived from password and network name.
Random packet number is used.
All subsequent operations are encrypted using session key.
Packet numbers start from zero and then are incremented.
Requests have even packet numbers.
Responses have odd packet numbers.
