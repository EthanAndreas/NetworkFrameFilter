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

### Application

- DNS
- BOOTP
- DHCP
- SMTP
- HTTP
- FTP
- POP3
- IMAP

## Verbosity

Verbosity is a number between 1 and 3. <br />
1 - Only essential informations (@Mac, @IP ...) and protocols' name <br />
2 - Essential informations and their complements (Length of the packet, Time to live ...)<br />
3 - All informations is printed<br />

## Filter

in work

## Authors

**Ethan Huret**

## Credit

You can find the assets used at the following address : <br />
<https://packetlife.net/captures/protocol/> <br />
With the download of the packets, you can compare the informations printed with the CloudShark given by packets. <br />
