## Libc Firewall Bypass For Free Fire 

# About The Hook =>
We Know all Some Modders are using vpn firewall to bypass the free fire Anticheat domains, Instead of using any vpn firewall i have made a better solution to bypass the anticheat domains of free fire using libc.so hook without using any vpn firewall


# How its works ?
Usually All Process on Android have to use directly or indirectly the libc.so for Networking tasks, We will take this advantage of libc.so, There are some main functions of libc like getaddrinfo, socket, connect which we can use to intercept and filter to block ips and domains of the game anticheat.

# How to use ?
Simply add the header file hooklibc.h on your project and when the libanogs.so is loaded on memory take a sleep of 5 seconds then call the function hookFunctions(), The sleep(5) of 5 seconds after anogs load is necessary other wise it will cause login problems or game will crash.

# About The Author 
Hello Modders iam Toxic The Author and creater of this bypass, Iam interested in reverse engineering and i am working in this field for about last 6 years 

# Contact Me 
[t.me/CacheTmp_DalVik](URL)

[t.me/CacheTmp_DalVik](URL)



