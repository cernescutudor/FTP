# FTP Server 🌐



A simple, lightweight, and efficient FTP server implementation in **C++**.🚀

---

## 📜 Overview
This repository contains a minimalistic FTP server implementation written in C++ that adheres to the specifications outlined in [RFC 959](https://datatracker.ietf.org/doc/html/rfc959). The server supports basic FTP functionalities such as file transfer, directory listing, and authentication.

It has been tested with the FTP client described [here](https://manpages.ubuntu.com/manpages/noble/man3/ftp.3erl.html), and is compatible with Unix-based system

---

## 🌟 Features
Here’s what you can do with this server:

- **✅ Basic FTP Commands**:
  - Upload files to the server
  - Download files from the server
  - List directory contents

- **🔒 Secure Directory Access**:
  - Only allow access to the `ServerResources/` directory

- **⚡ Lightweight Implementation**:
  - Optimized for efficiency and easy deployment

- **🔧 Planned Future Enhancements**:
  - Multithreading to handle multiple concurrent client connections

---

## 🚀 Installation
Follow these simple steps to set up and run the server:

```bash
# Clone the repository
git clone https://github.com/cernescutudor/FTP.git

# Navigate to the project directory
cd FTP
cd FTP-server

# Compile the server
gcc -o server server.cpp user_repository.cpp

# Run the server
./ftp_server
