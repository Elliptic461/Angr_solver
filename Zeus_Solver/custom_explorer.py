import angr
import time
import logging

logging.getLogger('angr').setLevel(logging.ERROR)

binary = './invoice_2318362983713_823931342io.pdf.exe'

proj = angr.Project(binary)

#skip the stalling loop by setting ESI to 1
@proj.hook(0x40a4be, length = 5)
def skip_stall_loop(state):
    state.regs.esi = 1

class ZeusExplorer(angr.ExplorationTechnique):
    # Define how many times a state can revisit the same address
    # in its recent history before being discarded as stuck in a loop
    LOOP_THRESHOLD = 200

    # Cap number of ocncurrent active states
    MAX_ACTIVE = 20

    def __init__(self):
        super().__init__()
        self.step_count = 0
    
    # Allow any extra keyword arguments and pass them through
    def step(self, simgr, stash='active', **kwargs):
        self.step_count += 10
        # Advance states forward
        simgr = simgr.step(stash=stash, n=10,  **kwargs)

        new_active = []
        # Loop through every active state
        for state in simgr.stashes[stash]:
            # Get last 50 basic block addresses this state has visited
            recent = list(state.history.bbl_addrs)[-50:]

            # Check if how many times the current address appear in the 50 recent blocks
            # If it appears more than 200 times. Do not add it to new_active
            if recent.count(state.addr) > self.LOOP_THRESHOLD:
                continue

            # Add to a "active list"
            new_active.append(state)
        
        # Replace the active stash with "good" states (No stuck states)
        simgr.stashes[stash] = new_active

        # Cap active states
        if len(simgr.stashes[stash]) > self.MAX_ACTIVE:
            simgr.stashes[stash] = simgr.stashes[stash][:self.MAX_ACTIVE]
        
        # Log every 500 steps
        if self.step_count % 500 == 0:
            addr = hex(simgr.active[0].addr)
            print(f"Step: {self.step_count} | "
            f"Active: {len(simgr.active)} | " 
            f"Dead: {len(simgr.deadended)} | "
            f"Addr: {addr}")
        return simgr

    def complete(self, simgr):
        if self.step_count >= 25000: # Increase this to allow explorer to step further
            return True
        if len(simgr.active) == 0:
            return True
        return False



state = proj.factory.entry_state(
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }
)

simgr = proj.factory.simulation_manager(state)

# Attach ZeusExplorer class to the simulation manager, every time simgr steps, calls my step()
simgr.use_technique(ZeusExplorer())

# Records current time
start = time.time()

#Runs the exploration until complete() returns true.
simgr.run()

# Calculates total elapsed time
elapsed = time.time() - start

# print result 
print(f"Total Time: {elapsed} | "
    f"Active: {len(simgr.active)} | "
    f"Dead: {len(simgr.deadended)} | "
    f"Errored: {len(simgr.errored)} | "
    )
