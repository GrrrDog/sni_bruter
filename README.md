sni bruter v0.1
==========

This is a TNS SNI virtual hosts bruteforcer PoC.

TLS (SSL) has an extension SNI (Server Name Identification). The extension adds the ability to use virtual hosts with SSL.
A browser must send the host name of the server which it wants to get in the first SSL request (HELLO) so the server can reply with the SSL certificate of the chosen virtual host.

There were 2 ideas when I started to write the tool.

The first is to implement a new kind of virtual host bruteforcing. Sometimes, we have problems with searching for virtual hosts. For example, when a web server returns the same reply for requests with any virtual host in Host-header. Or, worse, when a web server says “200 OK“ and changes each link in the reply with the value from “Host”. In such cases, it is hard to detect a real virtual host from a pile of false positives. 

So I’ve got the idea to brute virtual hosts on a deeper layer – SSL (TLS). At first glance, it was a good idea (see site below), because SSL certificates will be different for different virtual hosts. In addition, it’s hard to detect bruteforce on the server side, because we don’t make a full SSL connection, just one packet and one reply.

However, in case of a wildcard SSL certificate (like *.google.com), we cannot brute, as we will get the same certificate in any vhost. Another problem is a virtual host without an SSL certificate (probably the tastiest part for pentesters).
Nevertheless, concerning the last problem, I thought it may be possible to determine the existence of a virtual host by artifacts in SSL replies. So, the second idea was to check and investigate the behavior of different web servers against incorrect TNS SNI values.

I have tested against Nginx and Apache servers, but I cannot say anything very interesting. The replies were pretty much the same. But there are some exceptions. The first is that some servers add “SSL Alert header” in replies for incorrect values in SNI extension, and some reply without such a header.  The second case was with Google. For any nonexistent virtual host, Google servers return a very large special certificate with a hundred domains (alt subject). That’s so big that my tool cannot parse it (to get full content). However, you can check it with the Wireshark tool.

It’s just a PoC because a tool with such tiny functionality is not useful and the code is pretty ugly. But for some tests, it may be useful. 

If you want to test the tool, check this site about SNI configuration: https://sni.velox.ch 

If you find any interesting cases/artifacts, please inform me (agrrrdog at gmail.com)


The tool uses M2Crypto Python module. If you want to use it on Windows OS, you probably will have a problem with M2Crypto installation. Try next sequence, it works for me:
- http://slproweb.com/download/Win32OpenSSL_Light-1_0_1i.exe
- https://raw.githubusercontent.com/saltstack/salt-windows-install/master/deps/win32-py2.7/M2Crypto-0.21.1.win32-py2.7.msi
- easy_install m2crypto
