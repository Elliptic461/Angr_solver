import angr
import time
import logging

binary = './invoice_2318362983713_823931342io.pdf.exe'

# Only show warnings
logging.getLogger('angr').setLevel(logging.WARNING)

#Load binary
proj = angr.Project(binary)

# Use BFS, filling in any uninitialized memory or registers
state = proj.factory.entry_state( 
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

simgr = proj.factory.simulation_manager(state)

# Checking how long the exploration took
start = time.time()

# Step 500 times
for i in range(10):
    try:
        simgr.step(n=50)
    except Exception as e:
        print(f'Exception at step {(i+1)*5}: {e}')
    elapsed = time.time() - start
    addr = hex(simgr.active[0].addr)
    print(f"Step {(i+1)*50} | "
    f"Active: {len(simgr.active)} | "
    f"Dead: {len(simgr.deadended)} | "
    f"Errored: {len(simgr.errored)} | "
    f"Addr: {addr} | "
    f"Time: {elapsed}")

    if len(simgr.active) > 200:
        print(f"Path Explosion {len(simgr.active)} active states")
        break
    
    if len(simgr.active) == 0:
        print(f"All states Dead")
        break
    
# Print result
print(f"Active: {len(simgr.active)}")
print(f"Deadended: {len(simgr.deadended)}")
print(f"Errored: {len(simgr.errored)}")

if simgr.errored:
    print(f"Errors:")
    for e in simgr.errored[:10]:
        # Print why it crash
        print(f"{type(e.error).__name__}: {e.error}")
        # Print which address the state crash
        print(f"State at: {hex(e.state.addr)}")

if simgr.active:
    addrs = {}
    for s in simgr.active:
        addr = s.addr
        if addr in addrs:
            addrs[addr] = addrs[addr] + 1
        else:
            addrs[addr] = 1

    print("Where active states are stuck:")
    count = 0
    for addr, num in sorted(addrs.items(), key=lambda x: -x[1]):
        print(f"{hex(addr)}: {num} states")
        count += 1
        if count >= 10:
            break

print(f"Total time: {time.time() - start}")
    


