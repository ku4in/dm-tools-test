#!/usr/bin/env python3

# Taken from:
# https://github.com/twhiteman/pyDes/issues/2?ysclid=m2tm7gaord925620909

import sys
import pyDes

des = pyDes.des([232, 74, 214, 96, 196, 114, 26, 224])
passwd=sys.stdin.readline().strip()
passwd += (8 - len(passwd))*'\x00'
crypt = des.encrypt(passwd)

print(crypt.hex().upper())
