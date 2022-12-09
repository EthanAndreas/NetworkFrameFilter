# Network Frame Filter

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

## Launch

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

## Verbosity

Verbosity is a number between 1 and 3. <br />
1 - Essential informations of the frame (one line by frame) <br />
2 - Essential informations and their complements (one line by layer)<br />
3 - All informations is printed<br />

## Filter

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

### Filter in the shell

```bash
./bin/exe -o <interface> | grep <protocol> -C NUM

<protocol> correspond to the name print in the shell (for example : "Ethernet")
NUM is the number of lines you want to print around the protocol name 
```

## Authors

**Ethan Huret**

## Credit

You can find the assets used at the following address : <br />
<https://packetlife.net/captures/protocol/> <br />
With the download of the packets, you can compare the informations printed with the CloudShark given by packets. <br />
