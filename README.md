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
