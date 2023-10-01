#!/bin/sh

sudo sh ipsec_victim.sh $1 $2
sudo ./tcp_client 172.17.1.5 $2 -bp $1
