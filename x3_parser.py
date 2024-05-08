# coding: utf-8
"""
./nova/etc/leds/system.x3
./nova/etc/starter/system.x3
./nova/etc/ports/system.x3
./nova/etc/log-prefix/system.x3
./nova/etc/user/system.x3
./nova/etc/www/system.x3
./nova/etc/radius/system.x3
./nova/etc/pciinfo/system.x3
./nova/etc/loader/system.x3
./nova/etc/system_names/system.x3
./nova/etc/net-remote/system.x3
./nova/etc/services/system.x3

all: payload len (32bit) | payload |
payload: | unk(32bit) | offset (32bit) | xml length (32bit) | xml type (32bit)| ... | xml length (32bit) | xml type (32bit)|...
"""

import struct
import sys

#"www_system.x3"
if len(sys.argv) < 2:
	print("./x3_parser.py file")
	exit(0)

buf = open(sys.argv[1],'rb').read()

def u32(buf):
    return struct.unpack(">I",buf)[0]

def getu32():
	global now
	result = u32(buf[now:now+4])
	now += 4
	return result

def parse_tag(level):
	global now
	length = getu32()
	end = now + length
	#print(f"node len: {length}")
	tag = getu32()
	print("\n"+"  "*level+f"<{tag}",end='')
	attrib_size = getu32()
	#print(f"arrtrib size: {attrib_size}")
	nest = False
	while now < end:
		nest |= parse_attribute(level, nest)
	if (nest):
		print("\n"+"  "*level+f"</{tag}>",end='')
	else:
		print(f"/>",end="")

def parse_attribute(level, nest):
	global now
	length = getu32()
	tag = getu32()
	tag_type = getu32()
	#print(f"\tlen: {length}")
	#154 for www, 47 for pciinfo, 153 for loader but still wrong
	if tag_type >= 4: #tag == 154  or tag ==47:
		now -= 12
		if not nest:
			nest = True
			print(">",end='')
		parse_tag(level+1)
	else:
		print(f" ({tag})",end='=')
		#print(f"tag_type: {tag_type}", end='')
		count = getu32()
		#print(f"\tcount: {count}", end="")
		vsize = getu32()
		#print(f"\tvsize: {vsize}")
		#if tag_type == 1:
		if tag_type == 3 or tag_type == 2:
			#print(f"{u32(buf[now:now+4])}, {buf[now:now+vsize]}",end='')
			ele = []
			for i in range(count):
				ele.append(u32(buf[now:now+4]))
				now += 4
			if tag_type == 3:
				print("i32 ",end="")
			else:
				print("u32",end='')
			if count > 1:
				print(f"{ele}",end='')
			else:
				print(ele[0],end='')
			now += vsize
		elif tag_type == 1:
			ele = []
			for i in range(count):
				ele.append(f"{buf[now:now+1]}")
				now += 1
			if count > 1:
				print(f"{ele}",end='')
			else:
				print(ele[0],end='')
			now += vsize
		else:
			vsize += count
			print(f"{buf[now:now+vsize]}",end='')
			now += vsize
	return nest

cons = []
now = 0
total_size = getu32()
tag = getu32()
unk = getu32()
print(f"<{tag}>",end='')
while now < len(buf)-4:
	parse_tag(1)
print("\n"+f"</{tag}>",end='')

