#!/bin/bash
apt update
apt install john -y
unshadow /etc/passwd /etc/shadow > crackMe.txt
