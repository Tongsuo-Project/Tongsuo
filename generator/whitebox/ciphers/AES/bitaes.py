#-*- coding:utf-8 -*-

from whitebox.containers import Vector, Rect

from .sbox import bitSbox
from .linear import ShiftRow, MixColumn
from .keyschedule import KS_round

def BitAES(plaintext, key, rounds=10):
    bx = Vector(plaintext).split(16)
    bk = Vector(key).split(16)

    state = Rect(bx, w=4, h=4).transpose()
    kstate = Rect(bk, w=4, h=4).transpose()

    for rno in xrange(rounds):
        state = AK(state, kstate)
        state = SB(state)
        state = SR(state)
        if rno < rounds-1:
            state = MC(state)
        kstate = KS(kstate, rno)
    state = AK(state, kstate)

    state = state.transpose()
    kstate = kstate.transpose()
    bits = sum( map(list, state.flatten()), [])
    kbits = sum( map(list, kstate.flatten()), [])
    return bits, kbits

def AK(state, kstate):
    return state.zipwith(lambda a, b: a ^ b, kstate)

def SB(state, inverse=False):
    return state.apply(lambda v: Vector(bitSbox(v, inverse=inverse)))

def SR(state, inverse=False):
    for y in xrange(4):
        state.apply_row(y, lambda row: ShiftRow(row, y, inverse=inverse))
    return state

def MC(state, inverse=False):
    for x in xrange(4):
        state.apply_col(x, lambda v: map(Vector, MixColumn(v)))
    return state

def KS(kstate, rno):
    return KS_round(kstate, rno)

