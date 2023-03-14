# secretaccount-persistence-metasploit-module
Module Post Metasploit Framework

This module contains several post exploitation persistence tricks.
this module can give you a very strong footing and stay hidden. first the module will create a new user then add it to administrators group then hide the user created from login boot windows logo and module will remove windows malware signature every boot and module will modify registry to change administrator folder permissions so you can read write . then allow all users to create service with system account.

![Screnshoot](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/2_000.png)

# Installation

```
git clone https://github.com/wooxsec/secretaccount-persistence-metasploit-module
cd secretaccount-persistence-metasploit-module
mv persistence_accounts.rb ~/.msf4/modules/post/
```
go to metasploit then reload module with reload command
