"""Can a supervisor own the child's /dev/tty while keeping pipes on 0/1?"""
import os, pty, select, sys, time

r_in, w_in = os.pipe()    # supervisor -> child stdin
r_out, w_out = os.pipe()  # child stdout -> supervisor

child_code = r'''
import sys, os
sys.stderr.write("child: stdin isatty=%s stdout isatty=%s\n" % (os.isatty(0), os.isatty(1)))
try:
    t = open("/dev/tty", "r+b", buffering=0)
except OSError as e:
    sys.stderr.write("child: NO /dev/tty (%s)\n" % e); raise SystemExit(1)
sys.stderr.write("child: has /dev/tty\n")
line = sys.stdin.readline()                 # a "JSON-RPC frame" on the pipe
t.write(b"PROMPT? ")                        # the approval prompt on the tty
ans = t.readline()
sys.stdout.write("reply:%s|%s\n" % (line.strip(), ans.strip().decode()))
sys.stdout.flush()
'''

pid, master = pty.fork()
if pid == 0:
    os.dup2(r_in, 0); os.dup2(w_out, 1)
    for fd in (r_in, w_in, r_out, w_out):
        try: os.close(fd)
        except OSError: pass
    os.execv(sys.executable, [sys.executable, "-u", "-c", child_code])

os.close(r_in); os.close(w_out)
os.write(w_in, b'{"frame":1}\n')

seen = b""
deadline = time.time() + 6
while time.time() < deadline:
    rl, _, _ = select.select([master], [], [], 0.2)
    if rl:
        try: seen += os.read(master, 1024)
        except OSError: break
        if b"PROMPT?" in seen:
            os.write(master, b"y\n"); break
print("supervisor saw on tty:", seen.decode(errors="replace").strip())

out = b""
deadline = time.time() + 6
while time.time() < deadline:
    rl, _, _ = select.select([r_out], [], [], 0.2)
    if rl:
        chunk = os.read(r_out, 1024)
        if not chunk: break
        out += chunk
        if b"\n" in out: break
print("supervisor got on stdout pipe:", out.decode(errors="replace").strip())
os.waitpid(pid, 0)
