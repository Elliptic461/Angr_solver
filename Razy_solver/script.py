import angr

binary = '0933a85ab3fec609bef86496b9c5e0140ff7e9c75b1d9219fc6202b551f4283b'

proj = angr.Project(binary, auto_load_libs=False)

cfg = proj.analyses.CFGFast()


# Use to get the address of external function + internal function
for addr, func in cfg.kb.functions.items():
    print(f"{addr}: {func.name}")


print("\nFinding which subroutine calls these function:")
# Hard coded address in decimal
addr1 = 5242988 # WinHttpReadData

addr2 = 5242964 # WinHttpCrackUrl

addr3 = 5242952 # StrStrA

for caller in cfg.kb.functions.callgraph.predecessors(addr1):
    print(f"addr1: {cfg.kb.functions[caller].name}")

for caller in cfg.kb.functions.callgraph.predecessors(addr2):
    print(f"addr2: {cfg.kb.functions[caller].name}")

for caller in cfg.kb.functions.callgraph.predecessors(addr3):
    print(f"addr3: {cfg.kb.functions[caller].name}")

print("\nChecking sub_4010a0 calls:")
sub_4010a0_addr = 4198560

for caller in cfg.kb.functions.callgraph.successors(sub_4010a0_addr):
    print(f"sub_4010a0: {cfg.kb.functions[caller].name}")

print("\nVerifying the order:")

func = cfg.kb.functions[0x4010a0]

# Going through each basic block in the function in address order 
for i in sorted(func.block_addrs_set):
    block = proj.factory.block(i)

    # Examine instructions inside each block
    for j in block.capstone.insns:
        # Filter for call
        if j.mnemonic == "call":
            print(f"address, operand:{j.address, j.op_str}")


print("\nRead at those memory addresses")

for addr in [0x4020c4, 0x4020cc, 0x4020d4]:
    # Read 20 bytes from that address
    data = proj.loader.memory.load(addr, 20)
    # Parse string
    string = data.split(b'\0')[0].decode()
    # Print it 
    print(f"0x{addr:x}: {string}")

