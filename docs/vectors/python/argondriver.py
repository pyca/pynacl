#!/usr/bin/python
#

import argparse
import json
import random
import string
import subprocess
import sys


class argonRunner:
    GOODCHARS = string.ascii_letters + string.digits

    def __init__(self, args):
        self.exe = args.exe
        self.mnsaltlen = args.mnsaltlen
        self.mnpwlen = args.mnpwlen
        self.mndgstlen = args.mndgstlen
        self.mnmem = args.mnmem
        self.mniters = args.mniters
        self.mxsaltlen = args.mxsaltlen
        self.mxpwlen = args.mxpwlen
        self.mxdgstlen = args.mxdgstlen
        self.mxmem = args.mxmem
        self.mxiters = args.mxiters
        self.encoded = args.encoded
        self.rng = random.SystemRandom()
        self.version = args.version
        self.construct = args.construct
        self.maxcount = args.n
        self.count = 0

    def _runOnce(self, passwd, salt, dgst_len, maxmem, iters):
        argv = [
            self.exe,
            salt.encode("ascii"),
            "-t",
            "{:2d}".format(iters),
            "-m",
            "{:2d}".format(maxmem),
            "-l",
            "{:3d}".format(dgst_len),
            "-v",
            self.version,
        ]

        if self.encoded:
            argv.append("-e")
            mode = "crypt"
        else:
            argv.append("-r")
            mode = "raw"
        if self.construct == "argon2i":
            argv.append("-i")
        elif self.construct == "argon2d":
            argv.append("-d")
        elif self.construct == "argon2id":
            argv.append("-id")
        p = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        out, err = p.communicate(passwd.encode("ascii"))
        return dict(
            passwd=passwd,
            salt=salt,
            dgst_len=dgst_len,
            maxmem=2 ** maxmem,
            iters=iters,
            mode=mode,
            pwhash=out.decode("ascii").rstrip(),
            construct=self.construct,
        )

    def _genSalt(self):
        sltln = self.rng.randint(self.mnsaltlen, self.mxsaltlen)
        chrs = [self.rng.choice(self.GOODCHARS) for x in range(sltln)]
        return "".join(chrs)

    def _genPw(self):
        pwln = self.rng.randint(self.mnpwlen, self.mxpwlen)
        chrs = [self.rng.choice(self.GOODCHARS) for x in range(pwln)]
        return "".join(chrs)

    def __next__(self):
        if self.count >= self.maxcount:
            raise StopIteration
        psw = self._genPw()
        slt = self._genSalt()
        mem = self.rng.randint(self.mnmem, self.mxmem)
        iters = self.rng.randint(self.mniters, self.mxiters)
        dgstln = self.rng.randint(self.mndgstlen, self.mxdgstlen)
        rs = self._runOnce(psw, slt, dgstln, mem, iters)
        self.count += 1
        return rs

    def __iter__(self):
        return self

    next = __next__


if __name__ == "__main__":

    p = argparse.ArgumentParser()
    p.add_argument("-x", "--executable", dest="exe", required=True)
    p.add_argument(
        "-c", "--construction", dest="construct", type=str, default="argon2i"
    )
    p.add_argument("-v", "--version", dest="version", type=str, default="13")
    p.add_argument(
        "-e",
        "--encoded",
        dest="encoded",
        default=False,
        action="store_true",
    )
    p.add_argument(
        "-s", "--min-salt-len", dest="mnsaltlen", type=int, default=8
    )
    p.add_argument(
        "-S", "--max-salt-len", dest="mxsaltlen", type=int, default=8
    )
    p.add_argument(
        "-p", "--min-password-len", dest="mnpwlen", type=int, default=16
    )
    p.add_argument(
        "-P", "--max-password-len", dest="mxpwlen", type=int, default=16
    )
    p.add_argument(
        "-l", "--min-digest-len", dest="mndgstlen", type=int, default=64
    )
    p.add_argument(
        "-L", "--max-digest-len", dest="mxdgstlen", type=int, default=64
    )
    p.add_argument(
        "-m", "--min-memory-exponent", dest="mnmem", type=int, default=16
    )
    p.add_argument(
        "-M", "--max-memory-exponent", dest="mxmem", type=int, default=16
    )
    p.add_argument(
        "-t", "--min-time-opscount", dest="mniters", type=int, default=3
    )
    p.add_argument(
        "-T", "--max-time-opscount", dest="mxiters", type=int, default=3
    )
    p.add_argument("-n", "--count", dest="n", type=int, default=10)
    p.add_argument(
        "-w",
        "--output",
        dest="outfile",
        default=sys.stdout,
        type=argparse.FileType("w"),
    )

    args = p.parse_args()

    res = [x for x in argonRunner(args)]

    json.dump(res, args.outfile, indent=2, separators=(",", ": "))
