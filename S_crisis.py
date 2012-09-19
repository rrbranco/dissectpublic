"""
This script deobfuscate strings used by Crisis PE DLL
sent to function 0x1004FEF0.

MD5: f004e38040e3e00c6c83a315caa2bdcf
SHA1: d07c725e5f925324155ff4bf00573288c8fcb09f

The decode is basically a dec into each byte of the obfuscated string,
however, some of the obfuscated data are not directly retrieved just using
GetString() function and others are not pushed prior to the call.
Then, this script automate all of the tasks above, deobfuscating
all the strings sent to function 0x1004FEF0 which in fact only
loads functions using LoadLibrary/GetProcAddress.

Pedro Drimel Neto
@pdrimel
pedrodrimel (at) qualys\gmail (dot) com
"""

from idaapi import *

"""
This function deobfuscate the encoded string, it is 
basically a dec into each byte of the string
"""
def deobfuscate_string(str):
	str2 = []
	for s in str:
		str2.append(chr(int(s.encode('hex'), 16) - 1))
	return ''.join(str2)

"""
This function, given an address and a mnemonic, it
returns the last instruction address prior to the address
received within the mnemonic received
"""
def lookfor_mnemonic(addr, mnemonic):
	func = get_func(addr)
	lesser = 1000000
	if func is not None:
		for instr in FuncItems(func.startEA):
			if addr > instr:	# does not look for address greater than addr
								# which is the call to deobfuscate
				mnem = GetMnem(instr)
				if mnem == mnemonic:
					if (addr - instr) < lesser:
						lesser = addr - instr
						lesser_addr = instr
		return lesser_addr
	else:
		return None

"""
Given a list of hex, this function returns its
correspondent string
"""
def hex_to_str(hex):
	str = []
	for h in hex:
		str.append(chr(h))
	return ''.join(str)

"""
This function, given a function name, looks for code cross-reference
to it, grab the parameter which is sent to this function, deobfuscate
and update DB with its comment, then returns a list of deobfuscated strings
"""
def grab_strings(func_name):
	func_addr = LocByName(func_name)
	if func_addr == BADADDR:
		Message("Function %s not found\n" % func_name)
		return None
	
	funcs_deobfuscated = []
	byte_array = []
	for xref in XrefsTo(func_addr, 0):
		if xref.type == fl_CN or xref.type == fl_CF: # if code cross-reference is call near or call far
			addr = GetPrevFixupEA(xref.frm) - 1
			mnem = GetMnem(addr)
			if mnem != 'push': 	# some args to the deobfuscate function are called a few instructions before the call
								# example call to deobfuscate at 0x1004042A
				addr = lookfor_mnemonic(xref.frm, 'push')
				if addr is None:
					Warning("Unable to deobfuscate at 0x%x\n" % xref.frm)
					continue
			addr2 = Dfirst(addr)
			str_type = GetStringType(addr2)
			if str_type is None:
				byte = Byte(addr2)
				while byte != 0x0:
					byte_array.append(byte)
					addr2 = addr2 + 1
					byte = Byte(addr2)
				str = hex_to_str(byte_array)
				byte_array = []
			else:
				str = GetString(addr2, -1, str_type)
			
			str = deobfuscate_string(str)
			MakeComm(addr, str)
			if str not in funcs_deobfuscated:
				funcs_deobfuscated.append(str)

	if len(funcs_deobfuscated) != 0:
		return funcs_deobfuscated
	else:
		return None
	
def main():
	Message("\n")
	funcs_deobfuscated = grab_strings('f_deobfuscate')
	if funcs_deobfuscated:
		# Print list of functions
		funcs_deobfuscated.sort()
		for f in funcs_deobfuscated:
			print f

if __name__ == '__main__':
	main()