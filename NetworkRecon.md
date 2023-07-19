# Network Recon
[Reference Video](https://www.youtube.com/watch?v=pdgBU9MDAwE&t=22454s)

Good reference for enumerating various services: [https://github.com/beyondtheoryio/Enumeration-Guide](https://github.com/beyondtheoryio/Enumeration-Guide)

Another good reference: [https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md](https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md)

## ARP
command:
```
arp -a
```

## netstat
command:
```
netstat -ano
```

## nmap
command:
```
nmap -A -p- -Pn <ip>
```
- -Pn is used to continue the scanning process on a port even if a reply ping doesnt come back. (takes longer time but wont miss out any hidden services or ports)
- -A does all scan that is OS detection, version detection etc.
- -p- means all ports

- if ports 53,135,139,445 try doing the following scan
command:
```
nmap -p 53,135,139,445 --script=smb-enum-*  <target-ip>
```

command:
```
nmap -sC -p- <ip> --open
```
```
nmap --script "ldap* not brute" <ip>
```
```
nmap -p 139,445 --script=enum-smb* <ip>
```

## smbclient/smbmap 
- If ports 139/445 appear, it is best to enumerate for SMB.
- These port might suggest there is active directory present on that network.

smbclient command:
```
smbclient -N -L //<ip>
```
- -N stands for no authentication, -L sstands for list.

smbmap command:
```
smbmap -H <ip> -u anonymous -R
```
- -H stands for host, -u stands for user, -R means recursively find directories and files in the shares.


## dnsrecon
- If port 53 is open, we can check for zone transfer to identify addition subdomains.

command:
```
dnsrecon -d <ip> -t axfr
```

## msfconsole
- There is an auxiliary module used to enumerate dns

command:
```
use auxiliary/gather/enum_dns
set domain <ip>
run
```

## fping
- Inorder to detect all the hosts in a network, nmap doesnt do the job very well as it cant find hosts that dont have open port, hence it declares that the host is down.
- fping help in detecting these types of hosts.
- It does an entire ping sweep on the network to find hosts that are up.


command:
```
fping -a -g 10.0.0.1/24
```
nmap command:
```
nmap -sP 10.0.0.1/24
```
- -a stands for alive hosts only, -g is for the set of ip ranges to check.
- this nmap command doesnt show all the hosts that are up in the network.

## Evil-WinRM
- If credentials of a username and password is recieved and the windows host has port **5985** or **5986** open, it is best to try evil-winrm to check for authentication as the user.
command:
```
evil-winrm -u <username> -p <password> -i <windows-vitcimt-ip>
```
- If you get access to a host and if you want to drop futher exploitation tools using evil-winrm.
command (in the shell):
```
upload exploit.exe
```
- If you want to download a file from the victim host to the attacker machine.
command:
```
download winpeas.log
```