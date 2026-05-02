import angr
import time
import signal
import logging

binary = 'AAA._xe'

# Show only warnings
logging.getLogger('angr').setLevel(logging.WARNING)

# Timeout handler so a single step can't hang forever
class TimeoutError(Exception):
    pass

def handler(signum, frame):
    raise TimeoutError("Step timed out")

signal.signal(signal.SIGALRM, handler)

# Load the binary 
proj = angr.Project(binary, auto_load_libs=False)

# Filling in any uninitialized memory or registers
state = proj.factory.entry_state(
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }
)

simgr = proj.factory.simulation_manager(state)

# Checking how long the exploration took
start = time.time()

for i in range(10):
    try:
        # 20 second timeout per batch
        signal.alarm(20) 
        simgr.step(n=50)
        signal.alarm(0)   # cancel alarm
    except TimeoutError:
        print(f"Step {(i+1)*50} timed out after 20", flush=True)
        break

    elapsed = time.time() - start
    addr = hex(simgr.active[0].addr)

    print(f"Step {(i+1)*50} | "
          f"Active: {len(simgr.active)} | "
          f"Dead: {len(simgr.deadended)} | "
          f"Errored: {len(simgr.errored)} | "
          f"Addr: {addr} | "
          f"Time: {elapsed:.1f}s", flush=True)

    if len(simgr.active) > 30:
        print(f"Path Explosion: {len(simgr.active)} active states", flush=True)
        break

    if len(simgr.active) == 0:
        print("All states dead", flush=True)
        break

# Error report
if simgr.errored:
    print(f"Errors:")
    for e in simgr.errored[:10]:
        print(f"{type(e.error).__name__}: {e.error}")
        print(f"State at: {hex(e.state.addr)}")

# Print address of where active states is stuck
if simgr.active:
    addrs = {}
    for s in simgr.active:
        a = s.addr
        if a in addrs:
            addrs[a] += 1
        else:
            addrs[a] = 1
    print("Where active states are stuck:")
    count = 0
    for a, num in sorted(addrs.items(), key=lambda x: -x[1]):
        print(f"{hex(a)}: {num} states")
        count += 1
        if count >= 10:
            break

print(f"Total time: {time.time() - start}s")