# secretaccount-persistence-metasploit-module
Module Post Metasploit Framework

This module contains several post exploitation persistence tricks.
this module can give you a very strong footing and stay hidden.

![Screnshoot](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/1.png)

# What do modules do?

first the module will create a user(secret:P@ssw0rd123) with the Administrator group then hide it from the login menu by edit registry.
we can see the users we created with the undetected module in "other users" so they are slightly invisible and remain hidden

![Screnshoot](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/2.png)

we upload the payload with the default architecture with msfvenom but it's not detected wow? the module has removed all Windows Defender malware signatures so performing subsequent operations will not wake up Windows Defender

![Screnshoot](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/3.png)

with low privilege we can create service with local system privilege and can build backdoor chain

![Screnshoot](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/4.png)

without UAC bypass we can already read shared Administrator and login to system easily via SMB with tools like psexec/smbexec and similar like wmiexec

![Screnshoot](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/5.png)

# Installation

```
git clone https://github.com/wooxsec/secretaccount-persistence-metasploit-module
cd secretaccount-persistence-metasploit-module
sudo mv persistence_nighmares.rb /usr/share/metasploit-framework/exploits/windows/local/

```
run msfconsole in terminal and reload module using command reload_all
