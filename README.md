# NetworkFrameFilter 
[![version](https://img.shields.io/badge/version-0.0.1-blue.svg)](https://github.com/EthanAndreas/NetworkFrameFilter)
[![compiler](https://img.shields.io/badge/compiler-gcc-red.svg)](https://github.com/EthanAndreas/NetworkFrameFilter/blob/main/Makefile)
[![license](https://img.shields.io/badge/license-GPL_3.0-yellow.svg)](https://github.com/EthanAndreas/NetworkFrameFilter/blob/main/LICENSE)
[![author](https://img.shields.io/badge/author-EthanAndreas-blue)](https://github.com/EthanAndreas)

## Table of Contents
1. [Abstract](#abstract)
2. [Command](#command)
   1. [Online](#online)
   2. [Offline](#offline)
   3. [Help](#help)
3. [Protocols supported](#protocols-supported)
   1. [Network](#network)
   2. [Transport](#transport)
   3. [Application](#application)
4. [Additional tool](#additional-tool)
   1. [Verbosity](#verbosity)
   2. [Filtering](#filtering)
   3. [Documentation](#documentation)
   4. [Tests](#tests)
5. [Credits](#credits)

## Abstract

Analyze network frame on severals protocols such as Bootp, DNS, SMTP, DHCP etc... <br />
(refer to the documentation for the protocols supported). <br />
Availabilities of analyzing online frame on your Laptop's port, or offline with the assets given. <br />
<br />
Choose the level of information printed with the verbosity (by default all is printed). <br />
Choose particular protocols with the filter. <br />
<br />
The name of files in source and include repertories are prefixed by the number of the protocol's layer they are related to : <br />
1 - Physical <br />
2 - Network <br />
3 - Transport <br />
4 - Application <br />

## Command

### Online

```bash
sudo ./bin/exe -i <interface> -v <verbosity> -f <filter>
```

### Offline

```bash
./bin/exe -o <file> -v <verbosity> -f <filter>
```

### Help

```bash
./bin/exe -h
```

## Protocols supported

### Physical

- Ethernet

### Network

- IPv4
- ARP
- IPv6

### Transport

- UDP
- TCP
- SCTP
- ICMP

### Application

- DNS
- BOOTP
- DHCP
- SMTP
- HTTP
- FTP
- POP3
- IMAP
- Telnet

## Additional tool 

### Verbosity

Verbosity is a number between 1 and 3. <br />
1 - Essential informations of the frame (one line by frame) <br />
2 - Essential informations and their complements (one line by layer)<br />
3 - All informations is printed<br />

### Filtering

Filter is a string you enter for chosing a type of packet on online listening. <br />
The packet available are : <br />

- arp
- bootp
- dhcp
- dns
- ftp
- http
- imap
- pop3
- smtp
- telnet
- tcp
- udp

To select transport layer, you have to enter the protocol name. <br />
For example, if you want to see only the TCP packets, you have to enter : <br />

```bash
./bin/exe -i <interface> -f tcp
```

To select application protocol you need to input the port number. <br />
For example, if you want to listen only the DNS packets, you can enter : <br />

```bash
./bin/exe -i <interface> -f "udp port 53"
```

### Documentation

You can create the documentation with the following command : <br />

```bash
make docs
```

The documentation is available in the repertory "styles". <br />

### Tests

There is a bash script to test the possible error of the program with valgrind. <br />
The test is on the offline mode with all the assets given. <br />

```bash
make tests
```

## Credit

You can find the assets used at the following address : <br />
<https://packetlife.net/captures/protocol/> <br />
With the download of the packets, you can compare the informations printed with the CloudShark given by packets. <br />
