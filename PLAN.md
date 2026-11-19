# ASFT Roadmap

A prioritized list of improvements for ASFT. The core design is sound: the
X448 session key exchange, ChaCha20 + BLAKE2s packet protection, the keyed
counter permutation, end-to-end file MACs, and the resumable file transfer all
work as documented. The items below are about correctness, testability,
throughput on slow links, and unattended operation.

Ordering is a suggestion, not a commitment. Each section is usable on its own.

---

## 1. Correctness and robustness fixes

These are small, targeted changes that remove real field failures.

### 1.1 Filenames longer than 79 bytes are broken

**Done.** `asft_msg_rx_receive` no longer reads the filename from the first
packet (which carries only 79 payload bytes). The first-block branch verifies
the header MAC and length bounds only; the filename is copied and validated
once, after the whole message is received and the file MAC passes. Names up
to 255 bytes are supported.

### 1.2 A serial error kills the process

Every EIO in `asft_serial.c` calls `asft_serial_cleanup()` and the gateway and
node loops return 1. A USB-serial adapter unplug, a radio timeout, or a modem
reset therefore stops the daemon. The protocol resumes transfers across
connectivity loss already, so the fix is plumbing: on I/O error, close the
port and retry `asft_serial_init()` with exponential backoff instead of
returning.

### 1.3 No signal handling

SIGINT/SIGTERM currently terminates the process mid-transfer:

* session keys are not wiped,
* `.asft-XXXXXX` temp files are left in the receive directory,
* nothing is logged.

Add a handler that sets a stop flag, breaks both loops, deinitializes crypto,
and exits cleanly. Also clean stale `.asft-*` files at startup; nothing
removes them today.

### 1.4 `sync()` instead of `fsync()`

`asft_file.c` calls `sync()` after unlink (sender) and after rename
(receiver). That flushes every filesystem on the host and still does not
guarantee the rename is durable. Replace with:

* `fsync(fd)` before `close()` on the receive path,
* `fsync()` of the destination directory after `rename()`,
* drop the `sync()` on the sender, which buys nothing.

### 1.5 Configuration validation

`atoi()` is used for every numeric option with no range checks. Consequences:

* `backoff_time_max 0` produces a busy loop (`apply_error_backoff` sets the
  pause to now);
* a negative `retry_timeout` retransmits immediately;
* `mode` can appear twice; the last one wins silently;
* `node`, `gateway`, `retry_timeout`, and `backoff_time_max` are accepted in
  the wrong mode;
* labels are not validated even though they become directory names;
* a missing `port` is not detected until the first read fails;
* `to_*`/`from_*` directories are not checked at startup.

Add mode-aware option checking, numeric range parsing (use `strtol`, reject
trailing garbage), label validation (same rule as filenames: no `/`, `\`,
control characters, or leading dot; bounded length), a required `port` check,
and a startup check that every peer's directories exist and are usable (or
create them with an option).

### 1.6 Logging

* Add timestamps to log lines.
* Replace the `debug 0/1` boolean with a level (error/warn/info/debug).
* Make stdout line-buffered (or flush after each line). Under systemd stdout
  is block-buffered, so the final lines are lost on a crash.

---

## 2. Test harness (enabler for everything else)

There are no tests. `serial_packet_loss` shows the intent, but nothing
automates it. This section unblocks safe changes to the protocol.

### 2.1 Transport abstraction

Let `port` select a backend:

```
port /dev/ttyUSB0 1200      # real serial (default)
port null                   # discard / loopback
port unix:/run/asft.sock    # unix stream socket
port pty                    # pseudo-terminal pair
```

The null/unix/pty backends let a gateway and one or more nodes run against
each other on a single host, which makes integration tests and demos easy
without hardware.

### 2.2 Unit tests

* COBS encode/decode round trip, including all-zero input and 0xFF runs.
* `filename_is_safe()` boundary cases.
* Packet flag encode/decode.
* Config parser: duplicates, invalid keys, range errors, mode mismatches.
* Crypto known-answer tests: HKDF outputs, counter permutation and inverse,
  a full X448 handshake between two contexts, tamper detection, replay
  rejection, counter exhaustion, candidate-key switching.

### 2.3 Integration tests

* Bidirectional file transfer over `null`/`pty` with 0%, 10%, and 50% loss.
* Resume after killing one side mid-file.
* Key rotation in the middle of a large file.
* Rejected packets (bad MAC, replayed counter) do not abort the transfer.

### 2.4 Fuzzing

libFuzzer targets for `cobs_decode`, the packet parser, and the config
parser. All are reachable from untrusted input on the wire or on disk.

### 2.5 Build and CI

* `make check` target.
* Sanitizer build: `-fsanitize=address,undefined`.
* CI matrix: gcc and clang, debug and optimized.
* Default `CFLAGS` should include `-O2 -g` and hardening
  (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE -pie`,
  `-Wformat=2`).

---

## 3. Throughput and latency on slow links

### 3.1 Directory scan per packet

`asft_msg_tx_init()` does `opendir` + `lstat` over every candidate file on
every poll: the gateway calls it whenever a peer is ready and has no pending
message, the node calls it on every request. With a few hundred queued files
this is a lot of I/O for a 1200-baud link. Cache the scan results for a short
interval (configurable `scan_interval`, default 1 s) or use inotify.

### 3.2 Whole file in RAM

Both ends buffer the entire file (up to 1 MB) and compute the file MAC before
the first packet goes out. Stream in chunks instead: lower memory, earlier
first packet, and no long blocking MAC at pickup.

### 3.3 One block per round trip

A request carries one 100-byte block (`ASFT_BLOCK_LEN`) and waits for the
response before sending the next. On half-duplex radio links the turnaround
dominates. Add a window of N blocks per request, with cumulative ACK and
selective retransmission. This is the largest protocol-level throughput win.

### 3.4 Framing timing

* `tcdrain()` after `asft_serial_send()` so the process knows the frame left
  the UART before it starts listening (important for RS-485 direction
  control).
* Configurable inter-frame delay and TX/RX turnaround delay for radios and
  modems that need them.

### 3.5 Compression

Optional per-file compression (e.g. LZ4) with a flag in the message header.
For text and logs over LoRa, the gain is large. Compress before MAC so
integrity still covers the original data.

### 3.6 Rekey frequency

The session counter is one byte, so a key exchange runs every 255 packets
(~25 KB). Overhead is acceptable, but X448 is expensive on weak CPUs.
Consider a configurable session packet budget or a wider counter, depending
on measurements.

---

## 4. Operations and security

### 4.1 Key indirection

Today keys must be stored in the config file. Add `node node01
@/etc/asft/keys/node01` and `gateway gw @/etc/asft/keys/gw` so the config can
be world-readable. Warn at startup if the config or key file is group- or
world-readable.

### 4.2 Single-instance lock

`flock()` a lockfile (config path or cwd) at startup. Two instances sharing a
`to_*` directory or a serial port would corrupt state.

### 4.3 Status and statistics

* Counters: bytes/files sent and received, retransmits, MAC failures, rekeys,
  current peer backoff, current transfer name and progress.
* Expose them via a SIGUSR1 dump and/or a status file (e.g. `asft.status`).
* This is the minimum for monitoring an unattended link.

### 4.4 Protocol version

Add a version byte to the key exchange (or a flag bit). Without it there is
no compatible way to evolve the wire format.

### 4.5 Key exchange replay cache

The node answers replayed key exchange requests, which lets an attacker churn
the candidate ring (bounded, but noisy). A small nonce cache would drop
replays cheaply.

### 4.6 Retention and delivery policy

* `max_attempts` then move the file to a `failed_<label>` directory instead
  of retrying forever.
* Overwrite policy for incoming names (`overwrite`, `keep`, `rename`).
* Preserve mtime on receive.
* Optional include/exclude filename patterns.

### 4.7 Resume across restart

Transfers survive link loss but not process restart, because the whole
message is held in RAM. A small state/journal file would let a restarted
process continue a partially received file.

### 4.8 Blocked write timeout

`asft_serial_send()` can block indefinitely on a wedged port. Add a write
timeout or non-blocking mode with `poll()`.

---

## 5. Packaging and documentation

* Add a `LICENSE` file (there is none).
* `contrib/asft@.service` systemd unit, hardened
  (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`, `RestrictAddressFamilies`).
* `make install` with a sensible prefix and config path.
* `--help` / `--version`.
* README:
  * troubleshooting section (no response, fingerprint mismatch, permission
    denied on the tty),
  * document the 255-packet rekey interval and its cost,
  * document the receive file mode (currently 0600 from `mkstemp`) and the
    overwrite behavior,
  * threat model: what traffic analysis still reveals (file sizes, traffic
    timing), no node-to-node traffic, no cover traffic.

---

## Suggested sequence

1. **Correctness batch** (section 1): filename limit, serial reopen, signals,
   `fsync`, config validation, logging. Independent, low risk, high value.
2. **Test harness** (section 2): transport abstraction, `make check`, CI.
   Everything after this is safer to change.
3. **Slow-link throughput** (section 3): scan caching and framing timing
   first, then the multi-block window, then optional compression.
4. **Operations** (section 4): stats, key indirection, lock file, cleanup.
5. **Packaging** (section 5) alongside the above.

Open questions before starting:

* What is the deployment: LoRa, RS-485, SHDSL, baud rate, number of nodes?
* Do we prioritize robustness + tests, or go straight for a protocol feature
  (multi-block window, compression)?
