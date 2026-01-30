# ICQ/OSCAR Server

A lightweight ICQ server implementation using the OSCAR protocol, designed to work with classic ICQ clients like QIP 2005.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)
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

## Requirements

- Python 3.8 or higher
- No external dependencies (uses only standard library)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/icq-server.git
   cd icq-server
