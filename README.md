# ICQ/OSCAR Server

A lightweight ICQ server implementation using the OSCAR protocol, designed to work with classic ICQ clients like QIP 2005.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-GNU_GPL_v3.0-blue)
![Protocol](https://img.shields.io/badge/Protocol-OSCAR-orange.svg)

## ✨ Features

- **Authentication** - Secure login with password verification
- **Messaging** - Real-time message delivery between users
- **Contact List** - Server-side contact list storage (SSI)
- **Status Support** - Online, Away, DND, Free for Chat, Invisible, and more
- **Typing Notifications** - Real-time typing indicators
- **User Search** - Search users by UIN, nickname, or email
- **Offline Messages** - Store messages for offline users
- **SQLite Database** - Persistent storage for users and contacts
- **Packet Logging** - Debug mode with full packet capture

## Doesn't work right
- **Search by UIN**

## Requirements

- Python 3.8 or higher
- No external dependencies (uses only standard library)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Artemchik-Studio/oscar-icq-server.git
   cd icq-server

   

    Initialize the database with test users

    Bash

    python database.py init

    Start the server

    Bash

    python server.py

## Configuration

Edit config.py to customize server settings:

```Python

HOST = '0.0.0.0'
AUTH_PORT = 5190
BOS_PORT = 5191
BOS_HOST = '127.0.0.1'  # Your server's public IP for network access
```

 Client Configuration
```QIP 2005

    Go to Server/proxy on the login screen
    Set Server: 127.0.0.1 (or your server IP)
    Set Port: 5190
    Enter your UIN and password
```
Database Management

```Bash

# Create test users (111111, 222222, 333333 with password: password)
python database.py init

# Add a new user
python database.py add <uin> <password> [nickname]

# List all users
python database.py list

# Show user details
python database.py info <uin>

# Change password
python database.py passwd <uin> <new_password>

# Delete user
python database.py delete <uin>

# Add contact
python database.py addcontact <owner_uin> <contact_uin>

# Show statistics
python database.py stats
```
## 📁 Project Structure
```
icq-server/
├── config.py       # Server configuration
├── oscar.py        # OSCAR protocol (FLAP, SNAC, TLV)
├── database.py     # SQLite database and user management
├── handlers.py     # SNAC packet handlers
├── server.py       # Main server implementation
├── debug.py        # Packet logger and debugging tools
├── icq_server.db   # SQLite database (auto-created)
└── packets.log     # Packet log file
```
## Protocol Support
# Implemented SNAC Commands

## Overview

| Family | Name | Client→Server | Server→Client |
|--------|------|:-------------:|:-------------:|
| 0x0001 | GENERIC | 8 | 5 |
| 0x0002 | LOCATION | 3 | 2 |
| 0x0003 | BUDDY | 3 | 3 |
| 0x0004 | ICBM | 4 | 4 |
| 0x0009 | PRIVACY | 3 | 1 |
| 0x0013 | SSI | 12 | 3 |
| 0x0015 | ICQ_EXT | 1 | 1 |

## 🐛 Debugging

Packet logging is enabled by default. View real-time packet flow in console:

```text

======================================================================
[>>> IN] #42 14:32:15.234 from 127.0.0.1:54321 UIN:111111
  FLAP Channel: 0x02 (SNAC_DATA) | Size: 48 bytes
  SNAC: ICBM (0x0004/0x0006) ReqID=0x00000017

Configure in debug.py:

Python

packet_logger = PacketLogger(
    enabled=True,
    show_hex=True,
    log_to_file=True,
)
```
## Testing
    
    Start the server:
```
    python server.py

    Connect with two clients:
        Client 1: UIN 111111, Password password
        Client 2: UIN 222222, Password password

    Test messaging between clients
```

## License

This project is licensed under GNU GPL v3.0 License - see the LICENSE file for details.

## ⚠️ Disclaimer

This project is for educational and nostalgic purposes only. ICQ is a trademark of VK. This project is not affiliated with or endorsed by VK or the original ICQ developers.

<p align="center"> Made with ❤️ for the ICQ nostalgia community </p> 
