# Web Recon
[Reference Video](https://www.youtube.com/watch?v=pdgBU9MDAwE&t=136s)

## Notes:
- Just check for low hanging fruits like, version number, software, dirs like: /uploads, /robots.txt, /.git, /admin, /login, /backup, /cgi-bin.
- Check exploits for version numbers and software.
- Check for default creds of a particular software.
- Check what extension the files are loaded as (html, aspx, php etc.)
- Check the source page.
- Check the Networks Tab in developers console.
- ** If credentials dont work for the software, try it on different services like ssh, ftp, telnet etc.
- ** Find config files like config.php as there is high probability to find creds.

## Tool #1: Dig
- Check for zone transfers if port 53 is open in an nmap scan.  
- Used to find **zone tranfers** which helps to find additional subdomains. 
- Alternate tools are ffuf, sublister.
- If a website is vulnerable to **zone transfer** it will list the subdomains available for that website.
- Not necessarily exploitable, but can be report as an Information Disclosure.

command:
```
dig axfr @<target-ip> <target.domain>
```
- The domains retrieved can be added to /etc/hosts/ if practicing in a lab, to dig into these subdomains.

## Tool #2: Nikto
- Not very helpful, but still worth a shot.
command:
```
nikto -h <ip>
```

## Tool #3: Shadon.io
- Web interface to find all devices connected to internet.

## Tool #4: TheHarvester
- Used to gather email account of individuals in an organization.

command:
```
theHarvester -d <domain.com> -b google
```

## Tool #5: nslookup
- Used to gather basic info about websites like IP address, DNS etc. 
- Can be used if port 53 is open.

## Tool #6: whois
command:
```
whois google.com
```
- Give information related to the website such as who owns the website, email address associated with it,origin, name servers, phone numbers etc.

## Tool #7: WPScan
- Used for enumerating word press application in CTFs.
command:
```
wpscan --url <target-url> -e ap --plugins-detection aggressive -o wpscan.log
```

## Tool #8 Amass
- Used for enumerating subdomains.
- Gives better output than sublister.
command:
```
amass enum -passive -d domain.com
```

## Tool #9 CeWL
- Used for making wordlists for password or directory by crawling the website for particular words.
- Used for password sparing and bruteforcing or finding hidden directories or files.

## Tool #10 SQLMap
- To automate SQL injection we can use SQLMap.

## Tool #11 gobuster
- Tool to bruteforce directories and web pages.
command:
```
gobuster dir -u http://target.com -w /wordlists/wordlist.txt -b 302,404 -x html,php -o out.log
```

## Tool #12 FFUF
- Tool faster than gobuster
command:
```
ffuf -u http://target.com/FUZZ -w wordlists/wordlist.txt
```
## Commix
- Can be used to get a proper reverse shell from a Command Injection vulnerability