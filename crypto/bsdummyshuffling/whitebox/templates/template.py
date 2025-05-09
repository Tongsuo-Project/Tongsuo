#-*- coding:utf-8 -*-

import os, re, sys
DIR = os.path.dirname(os.path.abspath(__file__))

class Template(object):
    show_warnings = True # t = Template(...); t.show_warnings = False  to disable

    def __init__(self, name=None, filename=None, code=None):
        if name:
            filename = os.path.join(DIR, name)
            assert os.path.isfile(filename)

        if filename:
            self.code = open(filename).read()
        else:
            assert code
            self.code = code

    def subs(self, **repl):
        def rep(m):
            key = m.group(1)
            if key in repl:
                res = repl[key]
                if isinstance(res, tuple) or isinstance(res, list):
                    return ",".join(map(str, res))
                return str(repl[key])
            if self.show_warnings:
                print("WARNING: Template has unset variable %s" % m.group(0))
            return m.group(0)
        return re.sub(r"\$(\w+)\b", rep, self.code)


def encode_bytes(s):
    """
    this encoding includes raw symbols
    annoys many editors
    is very compact (can be improved by avoiding null bytes)
    idea by Vlad Roskov
    """
    return ", ".join(f"0x{b:02x}" for b in s)
