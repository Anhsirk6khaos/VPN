# VPN
A mini VPN created using C.

Developed a cross-platform VPN tool in C that enhances secure communication over untrusted networks through
encryption and data optimization. Utilized core C programming and network principles to create a tool that is
ideal for learning VPN protocols and C programming.

To run:

# General Compilation code:

gcc -c -Wall -std=c99 openssl_hostname_validation.c

gcc -g -I/usr/local/ssl/include -c tlsvpnfin.c

gcc -g -I/usr/local/ssl/include openssl_hostname_validation.o tlsvpnfin.o -o tlsvpnfin -L/usr/local/ssl/lib  -lssl -lcrypto -ldl

# Server code:


sudo ./tlsvpnfin-i tun0 -s -d

sudo ip addr add 10.0.1.1/24 dev tun0

sudo ifconfig tun0 up

sudo route add -net 10.0.2.0 netmask 255.255.255.0 dev tun0

# Client code:

sudo ./tlsvpnfin -i tun0 -c 192.168.15.4 -d

sudo ip addr add 10.0.2.1/24 dev tun0

sudo ifconfig tun0 up

sudo route add -net 10.0.1.0 netmask 255.255.255.0 dev tun0
