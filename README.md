windhcp-py
==========

A Python library to read and write to a Microsoft Windows Server DHCP Service

This library has the basic functionality of reading a DHCP server Scopes,exclusions,ranges,clients, and the additional feature of getting the free ip address in an arbitrary scope.

It can list,delete and write new reservations

It requires the windows server to have an ssh server running.

It leverages the netsh command on the windows cmd.exe command line


==========

02/10/2023 - cooperp12

Tested on Windows 11 and Ubuntu 22.04.1-Ubuntu with Python 3.11.5 using Windows Server 2022 (Trial)

To Python 3 and simplifying some code blocks. This code is by no means clean or optimised.


It demonstrates read and write for DHCP for Windows on any operating system.

Requires ssh server on the Windows Server and ssh client on the system it runs

python windhcp-release.py -s 192.168.XXX.XXX -u UserName
