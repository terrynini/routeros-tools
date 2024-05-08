_chrptr = gdb.lookup_type('char').pointer()
_chr = gdb.lookup_type('unsigned char')
import struct
import builtins
import traceback

def print(*objs, **kwargs):
    my_prefix = (len(traceback.format_stack())-baseDepth)*"  "
    builtins.print(my_prefix, *objs, **kwargs)

def parseM2(data):
    now = 0
    magic = data[now:now+2]
    now += 2
    if magic != b"M2":
        print("!!!! THIS IS NOT M2 !!!!")
        return
    while now < len(data):
        id_type = data[now:now+4]
        tagid = struct.unpack("<I",id_type[:3]+b'\x00')[0]
        tag = id_type[3]
        is_array = tag & 0b10000000
        sbit = tag & 0b1
        dtype = (tag & 0b00111000) >> 3
        #print(f"id_type {id_type}, tagid {tagid:x}, tag {tag:x}, dtype {dtype}, is_array {is_array} ",end=" = ")
        print(f"0x{tagid:x} = ",end="")
        now += 4
        if is_array:
            if sbit:
                array_size = data[now]
                now += 1
            else:
                array_size = struct.unpack("<H",data[now:now+2])[0]
                array_size_raw = data[now:now+2]
                now += 2
            array = []
            if dtype == 0:
                for i in range(array_size):
                    array.append(data[now])
                    now += 1
                print(f"bool: {array}")
            elif dtype == 1: 
                for i in range(array_size):
                    dtemp = struct.unpack('<I',data[now:now+4])[0]
                    stemp = f"{dtemp}({hex(dtemp)})"
                    array.append(stemp)
                    now += 4
                print(f"u32: {array} size {array_size} {array_size_raw}")
            elif dtype == 2:
                for i in range(array_size):
                    dtemp = struct.unpack('<Q',data[now:now+8])[0] 
                    stemp = f"{dtemp}({hex(dtemp)})"
                    array.append(stemp)
                    now += 8
                print(f"u64: {array}")
            elif dtype == 3:
                for i in range(array_size):
                    array.append(data[now:now+16])
                    now += 16
                print(f"IPv6: {array}")
            elif dtype == 4 or dtype == 6:
                for i in range(array_size):
                    temp_len = struct.unpack("<H",data[now:now+2])[0]
                    now += 2
                    arran.append(data[now:now+temp_len])
                    now += temp_len
                print(f"{'string' if dtype==4 else 'raw'}: {array}")
            elif dtype == 5:
                #for i in range(array_size):
                #    temp_len = struct.unpack("<H",data[now:now+2])[0]
                #    now += 2
                #    array.append(data[now:now+temp_len])
                #    now += temp_len
                #print(f"message array: {array}")
                print(f"message:")
                for i in range(array_size):
                    temp_len = struct.unpack("<H",data[now:now+2])[0]
                    now += 2
                    parseM2(data[now:now+temp_len])
                    now += temp_len
            else:
                print("unk type")
        else:
            if dtype == 0:
                print(f"bool: {'True' if sbit else 'False'}")
            elif dtype == 1: 
                if sbit:
                    print(f"u32: {data[now]}({hex(data[now])})") 
                    now += 1
                else:
                    dtemp = struct.unpack('<I',data[now:now+4])[0]
                    print(f"u32: {dtemp}({hex(dtemp)})")
                    now += 4
            elif dtype == 2:
                dtemp = struct.unpack('<Q',data[now:now+8])[0]
                print(f"u64: {dtemp}({hex(dtemp)})")
                now += 8
            elif dtype == 3:
                print(f"IPv6: {data[now:now+16]}")
                now += 16
            elif dtype == 4 or dtype == 6:
                if sbit:
                    temp_len = data[now]
                    now += 1 
                else:
                    temp_len = struct.unpack("<H",data[now:now+2])[0]
                    now += 2
                print(f"{'string' if dtype==4 else 'raw'}: {data[now:now+temp_len]}")
                now += temp_len
            elif dtype == 5:
                if sbit:
                    temp_len = data[now]
                    now += 1
                else:
                    temp_len = struct.unpack("<H",data[now:now+2])[0]
                    now += 2
                print(f"message: ")
                parseM2(data[now:now+temp_len])
                now += temp_len
            else:
                print("unk type")

baseDepth = 0
def msgSniffer(pos,length):
    global baseDepth
    baseDepth = len(traceback.format_stack())
    now = pos
    for idx in range(length):
        msg_len = gdb.parse_and_eval(f"*(int*){now+4}")
        msg = gdb.parse_and_eval(f"*(void**){now}")#.cast(_chrptr)
        temp = gdb.parse_and_eval(f"(char[{msg_len}])*{msg}")
        print(f"  -> msg@{hex(msg.cast(gdb.lookup_type('int')))} with length {msg_len.cast(gdb.lookup_type('int'))}")
        msg_content = bytes([int(temp[i].cast(_chr)) for i in range(msg_len)])
        print(msg_content)
        print("-"*5 + f"Start of {hex(msg.cast(gdb.lookup_type('int')))}" + "-"*5)
        print(f"size {struct.unpack('<I',msg_content[:4])[0]}")
        parseM2(msg_content[4:])
        print("-"*5 + f"End of {hex(msg.cast(gdb.lookup_type('int')))}" + "-"*5)
        print("")
        now += 8


gdb.execute("set follow-fork-mode parent")
gdb.execute("set pagination off")
gdb.execute("target remote 192.168.88.1:5566")
bp = gdb.Breakpoint('*0x4035f8')
bp.silent = True
count = 0 

while count < 10:
    gdb.execute("continue")
    fd=gdb.parse_and_eval("$a0")
    if fd in  [9,15,20]:#this depends on each execution
        continue
    pos=gdb.parse_and_eval("*(void**)($a1+0x8)")
    length=gdb.parse_and_eval("*(void**)($a1+0xc)")
    print(f"send to fd {fd}: msg_vector@{hex(pos.cast(gdb.lookup_type('int')))} with length {length.cast(gdb.lookup_type('int'))}")
    msgSniffer(pos, length)
    count += 1
print("delete breakpoints and continue")
bp.delete()
gdb.execute("detach")
