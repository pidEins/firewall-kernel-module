# firewall-kernel-module

This readme provides the kernle module which implements 3 firewall rules as mentioned below

1. Block all unsolicited ICMP packets coming in from outside except the ones going to the web-server. 
   However,the local hosts should be able to ping outside.
2. Block all ssh attempts from outside.
3. Block port 80 (http) access from outside except for the web-server and test that an internal website on a local host is only accessible from inside..

To build this module, please run the below mentioned command

- make 

To clean up the module, please run

- make clean

To install the module, please run 

- insmod firewall.ko

To verify that module is inserted properly 

- lsmod | grep -i firewall

To uninstall the module

- rmmod firewall
