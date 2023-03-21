# secretaccount-persistence-metasploit-module
Module Post Metasploit Framework

This module contains several post exploitation persistence tricks.
this module can give you a very strong footing and stay hidden.

![Screnshoot](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/1.png)

# What do modules do?

first the module will create a user(secret:P@ssw0rd123) with the Administrator group then hide it from the login menu by megedit registry

# Installation

```
git clone https://github.com/wooxsec/secretaccount-persistence-metasploit-module
cd secretaccount-persistence-metasploit-module
mv persistence_accounts.rb ~/.msf4/modules/post/
```
go to metasploit then reload module with reload command
