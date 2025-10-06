# Secure-programming
group 47 


1. Overview
-----------
Project Name: <Overlay Chat Protocol Reference Implementation>

Purpose:
A multi-party overlay chat system that implements the class-wide protocol. The goal is to explore protocol design trade-offs in programming, security, and vulnerability analysis.

Protocol & Scope:
- Overlay routing with message forwarding based on a routing table.
- Features:
  - List all currently online members.
  - Private messages to a single participant (forwarded to the correct destination).
  - Group/broadcast messages to all participants.
  - Point-to-point file transfer.
- Security considerations included in the design:
  - Secure the socket/channel used for data exchange.
  - Defend against malicious users of the program.
  - Consider malicious nodes and potential wiretapping of communication.
  - Maintain secure communication while forwarding/routing through an overlay topology.
  - Core functions include user registration and message send/receive with authentication.
- Interoperability:
  - Intended to interwork with other student groups' implementations that follow the same protocol.

Audience:
CLI users and developers from other groups who need to integrate with the class protocol.


2. Information
-------------
File Structure(we use server to run the code and show the chat system)
project/
├── src/
│   ├── server/
│   │   ├── server.py          # Main server entry point
│   │   ├── state.py           # State management
│   │   ├── bootstrap.py       # Network join protocol
│   │   ├── presence.py        # User presence gossip
│   │   ├── delivery.py        # Message forwarding
│   │   └── health.py          # Health monitoring
│   ├── client/
│   │   └── client.py          # Client application
│   ├── crypto/
│   │   └── rsa_crpt.py        # RSA encryption
│   └── utils/
│       └── json_utils.py      # JSON utilities



3. How to Run
-------------
Basic:
python -m src.server.server <port> <server_id> [--introducer] [--bootstrap <address>]

Parameters:
- `<port>` - Port number (e.g., 8765)
- `<server_id>` - Unique server identifier (e.g., server_1)
- `--introducer` - Flag to make this server an introducer/bootstrap server
- `--bootstrap <address>` - Address of introducer to join (format: host:port)


Steps:
*Multiple Bootstrap Servers :
'''bash
python -m src.server.server 8768 server_4 --bootstrap localhost:8765,localhost:8766

*Start introducer first
'''bash
python -m src.server.server 8765 server_1 --introducer

*Start joining servers:
'''bash
python -m src.server.server 8766 server_2 --bootstrap localhost:8765

*Server Logs Explained
- `[Bootstrap]` - Network join protocol messages
- `[Federation]` - Server-to-server connection events
- `[Presence]` - User join/leave announcements
- `[Delivery]` - Message routing between servers
- `[Health]` - Heartbeat and connection monitoring
- `[Server]` - Client connection events

4. Client Usage
------------
*Starting the Client
**Syntax:**
```bash
python -m src.client.client [server_address]
```
**Parameters:**
- `[server_address]` - Optional. Server to connect to (default: localhost:8765)
  - Can be full WebSocket URL: `ws://localhost:8766`
  - Or just port number: `8766`
**Examples:**
1. **Connect to default server (port 8765):**
```bash
python -m src.client.client
```
2. **Connect to specific server:**
```bash
python -m src.client.client 8766
```
3. **Connect using full URL:**
```bash
python -m src.client.client ws://localhost:8767
```
### Initial Connection

*When you start the client:
```
Server: ws://localhost:8766
Enter your username: Bob
[Bob] Connecting to ws://localhost:8766...
[Bob] Sent USER_HELLO
[Bob] Connected to ws://localhost:8766
[System] Alice joined!

*The client will:
1. Prompt for username
2. Generate RSA key pair
3. Send USER_HELLO to server
4. Receive list of existing users
5. Display when other users join

5. Command Reference
-----------
### /help - Show Command List
Displays all available commands.

### /list - List All Users
**Description:** Shows all users across all servers in the network.
**Output:**
```
[System] Online users:
  - Alice (a1b2c3d4-e5f6-7890-abcd-ef1234567890)
  - Bob (f9e8d7c6-b5a4-3210-fedc-ba0987654321)
  - Charlie (12345678-90ab-cdef-1234-567890abcdef)
```
**Notes:**
- Shows users from all connected servers
- Includes UUID for each user
- Updates automatically when users join/leave

### /tell - Send Private Message
example:
/tell <recipient> <message>

**Parameters:**
- `<recipient>` - Username or UUID of recipient
- `<message>` - Message text (can include spaces)

**Examples:**
```
/tell Alice Hello!
/tell Bob How are you doing?
/tell a1b2c3d4-e5f6-7890-abcd-ef1234567890 Using UUID
```

### /all - Broadcast to All Users
```
/all <message>
```
**Parameters:**
- `<message>` - Message text to broadcast

**Examples:**
```
/all Hello everyone!
/all Meeting in 5 minutes
```

### /file - Send File
```
/file <recipient> <filepath>
```

**Parameters:**
- `<recipient>` - Username or UUID of recipient
- `<filepath>` - Path to file (absolute or relative)

**Examples:**
```
/file Alice document.txt
/file Bob ~/Downloads/photo.jpg
/file Charlie /home/user/report.pdf
```

### /quit - Disconnect
```
/quit
```
**Description:** Closes connection and exits client.



