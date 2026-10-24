import sys, os, time
sys.stdout.reconfigure(encoding='utf-8')
import angr

output_lines = []

def log(msg):
    print(msg)
    output_lines.append(msg)

target = r'd:\New folder\SYMB\examples\02_smt_crackme\ais3_crackme'
log(f"[SYMB_CORE] Initializing Symbolic Execution Engine for target: {os.path.basename(target)}")
t0 = time.time()

proj = angr.Project(target, auto_load_libs=False)

# In angr 10+, use angr.claripy (Rust accelerated AST)
claripy = angr.claripy
key_sym = claripy.BVS('ais3_license_key', 100 * 8)

state = proj.factory.entry_state(args=['./crackme1', key_sym])
sm = proj.factory.simulation_manager(state)

log("[SYMB_CORE] Target Address: 0x400602 ('correct' message branch)")
log("[SYMB_CORE] Exploring state space with Z3 SMT constraint accumulator...")

sm.explore(find=0x400602)

if sm.found:
    t1 = time.time()
    found_state = sm.found[0]
    raw_sol = found_state.solver.eval(key_sym, cast_to=bytes)
    concrete_key = raw_sol[:raw_sol.find(b'\x00')].decode('utf-8', errors='ignore')
    
    log("\n" + "=" * 62)
    log("⚡ [SYMB_Z3_SOLVER] STATUS: SAT (Branch Reachable & Solved)")
    log(f"⚡ [SYMB_Z3_SOLVER] Convergence Time: {round((t1 - t0) * 1000, 2)} ms")
    log(f"★ [RECOVERED_SECRET_KEY]: \"{concrete_key}\"")
    log("=" * 62 + "\n")
else:
    log("[-] SMT State Space: UNSAT")

with open(r'd:\New folder\SYMB\examples\02_smt_crackme\ais3_result.txt', 'w', encoding='utf-8') as f:
    f.write("\n".join(output_lines))
