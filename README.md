Note; this repository makes references to external repositories (known as Git submodules). After cloning this repository, please make sure to run the following commands to clone those submodules:

    git submodule init
    git submodule update 

BlueBox
=======

BlueBox is a collection of scripts and configurations for the automated exploitation of [MS15-122](https://technet.microsoft.com/en-us/library/security/ms15-122.aspx) and [MS16-014](https://technet.microsoft.com/en-us/library/security/ms16-014.aspx), (see also [CVE-2015-6095](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6095) and [CVE-2016-0049](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0049)).

Additional information about this vulnerability can be found in the [BlackHat EU 2015 presentation and whitepaper](https://www.blackhat.com/eu-15/briefings.html#ian-haken) made on this topic, or the [updated talk](http://www.slideshare.net/ianhaken/attacking-windows-authentication-and-bitlocker-full-disk-encryption) presented at BSides Seattle 2015.

This exploit allows an attacker to bypass the login screen of Windows machines using domain authentication. This can be used to read a user's data, bypassing full disk encryption protections, to quickly attack unattended machines in order to plant a remote access toolkit or other malware, and can be used to do either of the above without taking the machine offline.

For a quick demostration, I've recorded the following videos:

BlueBox: Opportunistic Laptop Attack  
<a href="http://www.youtube.com/watch?feature=player_embedded&v=LT0Z9asOedM" target="_blank"><img src="http://img.youtube.com/vi/LT0Z9asOedM/0.jpg" alt="BlueBox: Opportunistic Laptop Attack" width="240" height="180" border="10" /></a>

BlueBox: Zero-Downtime Attack  
<a href="http://www.youtube.com/watch?feature=player_embedded&v=cz6PgGEw4_Y" target="_blank"><img src="http://img.youtube.com/vi/cz6PgGEw4_Y/0.jpg" alt="IMAGE ALT TEXT HERE" width="240" height="180" border="10" /></a>

This repository includes some init-scripts and configuration files for deployment of these scripts on a Debian-based system (the aforementioned demo runs on [Raspbian](https://www.raspbian.org/), a Debian distribution for the Raspberry Pi). However, there is no particular need to run these tools on that platform; you could just as easily configure a regular laptop and arbitrary operating system to run these Python scripts and a DHCP server.

The scripts in the [init-scripts](init-scripts) subdirectory can be used to start the malicious servers on boot; this is particularly useful when utilizing a headless dedicated device (like the Raspberry Pi). You can place those scripts in `/etc/init.d` and run

    update-rc.d evil-server-{dns,kdc,ldap,netbios} defaults

This repository has configurations for two styles of deployment; as a simple lockscreen bypass tool, or as a zero-downtime attack tool. Further description and configuration instructions are below.

BlueBox Lockscreen Bypass
-------------------------

The intended use of this configuration would be to opportunistically gain access to a client workstation, such as an unattended laptop. The deployment requires an independent DHCP server; an example configuration file for the [ISC DHCP Server](https://www.isc.org/downloads/dhcp/) is [available](configs/bluebox/dhcpd.conf). Several of the malicious servers are hardcoded to refer to the current machine as at IP address 192.168.0.1, so a sample [network configuration](configs/bluebox/interfaces) is included which gives eth0 this static IP.

Although not necessary, you may also choose to install an FTP/HTTP server on the host machine in order to serve a malicious payload that can be executed by the attacker on the victim machine.

Zero-Downtime Attack Tool
-------------------------

This configuration requires two physical ethernet devices and allows the attack device to function in a man-in-the-middle capacity. This configuration bridges the two ethernet devices to allow traffic to pass through unchanged, making the device transparent on the network. However, its netfilter configuration will redirect Kerberos traffic to the localhost (that is, to the malicious server) which allows an attacker to bypass the login screen of a live server.

In order to deploy this configuration, your ethernet devices should be configured [to be bridged](configs/zerodown/interfaces). The configuration requires use of netfilter on the bridge interface, so you need to add the `br_netfilter` module to `/etc/modules`. In order to configure ebtables and iptables to hijack Kerberos traffic, you should place the [ebtables](configs/zerodown/ebtables) configuration in `/etc/network/if-up.d/` directory, the [iptables](configs/zerodown/iptables) script in the `/etc/network/if-pre-up.d/` directory, and the [iptables.up.rules](configs/zerodown/iptables.up.rules) file in `/etc`.

This configuration also hijacks HTTP traffic destined for 10.254.254.254 and redirects it to a local server, which can be utilized as a convenient way to download a malicious payload to the victim machine. If doing this, the machine should also have some sort of webserver (e.g. apache2) installed.
