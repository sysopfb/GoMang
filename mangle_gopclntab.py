"""
Code based on https://github.com/sibears/IDAGolangHelper

Also Ref: https://github.com/strazzere/golang_loader_assist Specifically: https://github.com/strazzere/golang_loader_assist/blob/master/Bsides-GO-Forth-And-Reverse.pdf

Rewrote to not require IDA and to be used for mangling the gopclntab for 32 bit x86 files only, technique will work for other arch types but I decided to only release this portion.

By Jason Reaves (@sysopfb)
"""

import binascii
import random
import string
import struct



lookup = binascii.unhexlify("FBFFFFFF0000")

def check_is_gopclntab(data, off):
    (first_entry, first_entry_off) = struct.unpack_from('<II', data[off+12:])
    func_loc = struct.unpack_from('<I', data[first_entry_off+off:])[0]
    if func_loc == first_entry:
        return True
    return False


def findGoPcLn(data):
    possible_loc = data.find(lookup)
    while possible_loc != -1:
        if check_is_gopclntab(data, possible_loc):
            return possible_loc
        else:
            #keep searching till we reach end of binary
            possible_loc = data[possible_loc+1:].find(lookup)
    return None


def zero_gopclnstruct(data):
	loc = findGoPcLn(data)
	temp = data
	if loc != None:
		temp = data[:loc+8]+'\x00\x00\x00\x00'+data[loc+8+4:]
	return temp



def get_string(data, offset):
    t = data[offset:].split('\x00')[0]
    return t


def gen_random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(length))


def mangle_names(beg, data):
    out = data
    base = beg
    pos = beg + 8
    size = struct.unpack_from('<I', data[pos:])[0]
    pos += 4
    end = pos + (size * 4 * 2)
    while pos < end:
        offset = struct.unpack_from('<I', data[pos+4:])[0]
        pos += 4*2
        name_offset = struct.unpack_from('<I', data[base+offset+4:])[0]
        name = get_string(data, base+name_offset)
        new_s = gen_random_string(len(name))
        out = out[:base+name_offset] + new_s + out[base+name_offset+len(new_s):]
    return out

