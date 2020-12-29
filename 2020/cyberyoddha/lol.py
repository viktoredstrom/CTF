import angr # Import angr library
import claripy



p=angr.Project('./babyrev',auto_load_libs=False) #Loader

n = len("3E3?6]QHKTHQQBEETTNKZQ]K]?K<KHH<BQ<KQT<QHNT")

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(n)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

state = p.factory.full_init_state(
            args=['./babyrev'],
            add_options=angr.options.unicorn,
            stdin=flag,
)


known = [
    "CYCTF{l_dxhqr_dcsld_rhw_wdr_snn_ez_glp_ymw}"
]


state.solver.add(flag_chars[0] == ord('C'))
state.solver.add(flag_chars[1] == ord('Y'))
state.solver.add(flag_chars[2] == ord('C'))
state.solver.add(flag_chars[3] == ord('T'))
state.solver.add(flag_chars[4] == ord('F'))
state.solver.add(flag_chars[5] == ord('{'))
for k in flag_chars[6:]:
    state.solver.add(k < 0x80 - 1)
    state.solver.add(k > 0x32)
    state.solver.add(k != ord("`"))
    state.solver.add(k != ord("]"))
    state.solver.add(k != ord("^"))
    state.solver.add(k != ord("|"))
    state.solver.add(k != ord("{"))

state.solver.add(flag_chars[-1] == ord("}"))

def check(state):
    stdout = state.posix.dumps(sys.stdout.fileno())
    return (b'no flag for you' not in stdout) and (stdout != b'')

# Create a state, the default is the entry address of the program


# Create a simulator to simulate program execution, traversing all paths
ex = p.factory.simulation_manager(state)

FIND = 0x400000 + 0x12f5
AVOID = [0x400000 + 0x1303]
ex.use_technique(angr.exploration_techniques.Explorer(find=FIND, avoid=AVOID))
ex.run()

print (len(ex.found)) #.posix.dumps(0))
print (ex.found[0].posix.dumps(0))