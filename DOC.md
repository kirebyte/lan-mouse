# General Software Architecture

## Events

Each instance of lan-mouse can emit and receive events, where
an event is either a mouse or keyboard event for now.

The general Architecture is shown in the following flow chart:
```mermaid
graph TD
    A[Wayland Backend] -->|WaylandEvent| D{Input}
    B[X11 Backend] -->|X11Event| D{Input}
    C[Windows Backend] -->|WindowsEvent| D{Input}
    D -->|Abstract Event| E[Emitter]
    E -->|Udp Event| F[Receiver]
    F -->|Abstract Event| G{Dispatcher}
    G -->|Wayland Event| H[Wayland Backend]
    G -->|X11 Event| I[X11 Backend]
    G -->|Windows Event| J[Windows Backend]
```

### Input
The input component is responsible for translating inputs from a given backend
to a standardized format and passing them to the event emitter.

### Emitter
The event emitter serializes events and sends them over the network
to the correct client.

### Receiver
The receiver receives events over the network and deserializes them into
the standardized event format.

### Dispatcher
The dispatcher component takes events from the event receiver and passes them
to the correct backend corresponding to the type of client.


## Requests

// TODO this currently works differently

Aside from events, requests can be sent via a simple protocol.
For this, a simple tcp server is listening on the same port as the udp
event receiver and accepts requests for connecting to a device or to
request the keymap of a device.

```mermaid
sequenceDiagram
    Alice->>+Bob: Request Connection (secret)
    Bob-->>-Alice: Ack (Keyboard Layout)
```

## Problems
The general Idea is to have a bidirectional connection by default, meaning
any connected device can not only receive events but also send events back.

This way when connecting e.g. a PC to a Laptop, either device can be used
to control the other.

It needs to be ensured, that whenever a device is controlled the controlled
device does not transmit the events back to the original sender.
Otherwise events are multiplied and either one of the instances crashes.

To keep the implementation of input backends simple this needs to be handled
on the server level.

## Device State - Active and Inactive
To solve this problem, each device can be in exactly two states:

Either events are sent or received.

This ensures that
- a) Events can never result in a feedback loop.
- b) As soon as a virtual input enters another client, lan-mouse will stop receiving events,
which ensures clients can only be controlled directly and not indirectly through other clients.


## Clipboard
The clipboard follows the cursor: when the cursor enters a remote device,
the local clipboard is pushed to it, and when the cursor returns (the
remote device sends `Leave`, the release bind is pressed or the client is
deactivated), the clipboard of the remote device is pulled.
The local clipboard is only read at these moments - there is no polling.

Both requests are initiated by the capturing device, so only the listening
side has to accept clipboard connections. Since clipboard contents can be
large (e.g. screenshots), they are not sent over the DTLS event channel but
over a separate TLS 1.3 connection (TCP, same port number), one request per
connection (see `src/clipboard/proto.rs`).

Authentication reuses the DTLS certificates:
- the listening side only accepts client certificates from the list of
  authorized fingerprints,
- the connecting side only accepts the certificate the peer presented over
  DTLS, so the clipboard is only ever sent to the device that also receives
  the input events.

Content offering the `x-kde-passwordManagerHint` mime type with the value
`secret` (set by password managers such as KeePassXC) is only sent if
`clipboard_allow_secrets` is enabled. Secrets are marked the same way on the
receiving device, so clipboard managers there do not keep them in history.

Clipboard sharing is disabled by default (`clipboard = true` enables it).
Currently only a Wayland backend (`wlr-data-control` / `ext-data-control`)
exists; on other platforms clipboard requests fail with an error status
and input sharing is not affected.
