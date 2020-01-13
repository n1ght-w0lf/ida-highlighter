import idc
import idaapi
import idautils

#wait for IDA to complete analysis
idaapi.autoWait()

#colors in hex 0xBBGGRR
DEFAULT_COLOR = 0xffffffff
CALL_COLOR = 0x0a6a0a
XOR_COLOR = 0x8a0a8a
ANITDEBUG_COLOR = 0x0a0a8a

def highlight_insn(ea, color, comment="", repeatable=0):
	idc.set_color(ea, CIC_ITEM , color)
	idc.set_cmt(ea, comment, repeatable)

def highlight_anti_debug():
	funs = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
		"OutputDebugString", "QueryPerformanceCounter", "GetTickCount"]
	for func in funs:
		func_ea = get_name_ea_simple(func)
		xrefs = list(idautils.CodeRefsTo(func_ea, 0))
		for ea in xrefs:
			highlight_insn(ea, ANITDEBUG_COLOR, "Possible Anti-Debugging")

def main():
	for func in idautils.Functions():
		#get function flags
		flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
		
		# skip library & thunk functions
		if flags & FUNC_LIB or flags & FUNC_THUNK:
			continue

		dism_addr = list(idautils.FuncItems(func))
		for ea in dism_addr:
			mnem = idc.print_insn_mnem(ea)

			if mnem == "call":
				highlight_insn(ea, CALL_COLOR)

			elif mnem == "rdtsc":
				highlight_insn(ea, ANITDEBUG_COLOR, "Possible Anti-Debugging")

			elif mnem == "xor":
				op1 = idc.print_operand(ea, 0)
				op2 = idc.print_operand(ea, 1)
				if op1 == op2:
					highlight_insn(ea, DEFAULT_COLOR, "{} = 0".format(op1))
				else:
					highlight_insn(ea, XOR_COLOR, "Possible enc/dec")

	highlight_anti_debug()

if __name__ == "__main__":
	main()
