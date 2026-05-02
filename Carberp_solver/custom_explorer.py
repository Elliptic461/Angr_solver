import angr
import time
import signal
import logging

binary = 'AAA._xe'
logging.getLogger('angr').setLevel(logging.WARNING)

# Timeout Handler

class TimeoutError(Exception):
    pass

def handler(signum, frame):
    raise TimeoutError("Timed out")

signal.signal(signal.SIGALRM, handler)

# SimProcedure Hooks 

class GetACPHook(angr.SimProcedure):
    def run(self):
        return 1252

class GetOEMCPHook(angr.SimProcedure):
    def run(self):
        return 437

class GetSystemDefaultLangIDHook(angr.SimProcedure):
    def run(self):
        return 0x0409

class GetLocaleInfoWHook(angr.SimProcedure):
    def run(self, locale, lctype, lpLCData, cchData):
        return 0

class LoadLibraryAHook(angr.SimProcedure):
    def run(self, lpLibFileName):
        return 0x10000

class RemoveDirectoryAHook(angr.SimProcedure):
    def run(self, lpPathName):
        return 1

class DeleteFileAHook(angr.SimProcedure):
    def run(self, lpFileName):
        return 1

class GlobalAllocHook(angr.SimProcedure):
    def run(self, uFlags, dwBytes):
        size = self.state.solver.eval(dwBytes)
        addr = self.state.heap.allocate(size)
        return addr

class SkipInt3(angr.SimProcedure):
    def run(self):
        self.jump(0x411BB0)

# Custom ExplorationTechnique 

class CarberpExplorer(angr.ExplorationTechnique):
    def __init__(self, proj, max_active=20):
        super().__init__()
        self.proj = proj
        self.max_active = max_active
        self.seen_addrs = set()
        self.text_start = 0x401000
        self.text_end = 0x413EC0

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        for s in simgr.stashes[stash]:
            self.seen_addrs.add(s.addr)

        # Categorize states
        valid = []
        for s in simgr.stashes[stash]:
            addr = s.addr
            if addr == 0x0:
                simgr.stashes.setdefault('found', []).append(s)
            elif self.text_start <= addr <= self.text_end:
                valid.append(s)
            elif self.proj.is_hooked(addr):
                valid.append(s)
        simgr.stashes[stash] = valid

        # Prune to max
        if len(simgr.stashes[stash]) > self.max_active:
            states = sorted(
                simgr.stashes[stash],
                key=lambda s: s.addr,
                reverse=True
            )
            simgr.stashes[stash] = states[:self.max_active]

        return simgr

# Setup

proj = angr.Project(binary, auto_load_libs=False)

# Hook API calls
proj.hook_symbol('GetACP', GetACPHook())
proj.hook_symbol('GetOEMCP', GetOEMCPHook())
proj.hook_symbol('GetSystemDefaultLangID', GetSystemDefaultLangIDHook())
proj.hook_symbol('GetLocaleInfoW', GetLocaleInfoWHook())
proj.hook_symbol('LoadLibraryA', LoadLibraryAHook())
proj.hook_symbol('RemoveDirectoryA', RemoveDirectoryAHook())
proj.hook_symbol('DeleteFileA', DeleteFileAHook())
proj.hook_symbol('GlobalAlloc', GlobalAllocHook())

# Skip INT 3 anti-debug sled
proj.hook(0x411BAB, SkipInt3(), length=5)

# Hook data section addresses used as function pointers
for addr in [0x426c40, 0x426c4c, 0x426c50, 0x426c54,
             0x426c58, 0x426c5c, 0x426c60, 0x426c64,
             0x426c78, 0x426c94, 0x426cac, 0x426cb0,
             0x426cc4, 0x426cc8, 0x426cf0, 0x426cf4]:
    proj.hook(addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](), length=4)

# Create entry state
state = proj.factory.entry_state(
    add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }
)

simgr = proj.factory.simulation_manager(state)
explorer = CarberpExplorer(proj, max_active=20)
simgr.use_technique(explorer)


# Run Setup 

start = time.time()

# run up to 1000 individual steps
for i in range(1000):
    try:
        signal.alarm(30) # Set a 30 second timer before each step
        simgr.step()
        signal.alarm(0)
    except TimeoutError:
        print(f"Step {i} timed out", flush=True)
        break

    # Prints a status update every 50 steps
    if i % 50 == 0:
        elapsed = time.time() - start
        addr = hex(simgr.active[0].addr) if simgr.active else "N/A"
        print(f"Step {i} | "
              f"Active: {len(simgr.active)} | "
              f"Dead: {len(simgr.deadended)} | "
              f"Errored: {len(simgr.errored)} | "
              f"Found: {len(simgr.stashes.get('found', []))} | "
              f"Addr: {addr} | "
              f"Time: {elapsed}s", flush=True)

    if len(simgr.active) == 0:
        print("All states dead", flush=True)
        break

#  Print results
print(f"Active:{len(simgr.active)}")
print(f"Deadended:{len(simgr.deadended)}")
print(f"Errored:{len(simgr.errored)}")
print(f"Completed:{len(simgr.stashes.get('found', []))}")
print(f"Unique addresses reached:{len(explorer.seen_addrs)}")

# Print error if any
if simgr.errored:
    print(f"Errors:")
    for e in simgr.errored[:10]:
        print(f"{type(e.error).__name__}: {e.error}")
        print(f"State at: {hex(e.state.addr)}")

# Count how many active states are stuck at each address
# Print them sorted by frequency.
if simgr.active:
    addrs = {}
    for s in simgr.active:
        a = s.addr
        addrs[a] = addrs.get(a, 0) + 1
    print("Where active states are:")
    for a, num in sorted(addrs.items(), key=lambda x: -x[1]):
        print(f"{hex(a)}: {num} states")

# Print all unique addresses reached, sorted
print(f"All unique addresses reached:")
for addr in sorted(explorer.seen_addrs):
    print(f"{hex(addr)}")

# Print total time
print(f"Total time:{time.time() - start}")



