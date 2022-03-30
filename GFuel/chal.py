#!/usr/bin/python3
# This flag comes from Taiwan's EOF CTF, 2022.
import random
import hashlib

q, r, s = 19, 39, 60
rc = [7, 9, 11, 13]
T = [[1, 1, 2, 12],
     [6, 1, 1, 2],
     [1, 6, 1, 1],
     [12, 1, 6, 1]]
Sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]

state = [0] * 82

def multx(p):
    if p >> 3:
        p = (p << 1) ^ 0x10
        p ^= 9
    else:
        p <<= 1
    return p

def mult(p1, p2):
    p = 0
    for i in range(4):
        t = p2
        if p1 & 1 << 3-i:
            for j in range(3-i):
                t = multx(t)
            p ^= t
    return p

def multM(v, M):
    v1 = [0] * 4
    for i in range(4):
        for j in range(4):
            v1[i] ^= mult(v[j], M[i][j])
    return v1

def computeT(S):
    fp = S[0] ^ S[7] ^ S[10] ^ mult(S[6], S[18])
    fq = S[0+q] ^ S[4+q] ^ S[6+q] ^ S[7+q] ^ S[15+q] ^ mult(S[3+q], S[7+q])
    fr = S[0+r] ^ S[1+r] ^ S[15+r] ^ S[17+r] ^ S[19+r] ^ mult(S[13+r], S[15+r])
    fs = S[0+s] ^ S[1+s] ^ mult(S[4+s], S[10+s]) ^ mult(S[11+s], S[18+s])

    gp = S[9+q] ^ S[10+r] ^ S[12+s]
    gq = S[4] ^ S[2+r] ^ S[5+s]
    gr = S[12] ^ S[11+q] ^ S[16+s]
    gs = S[16] ^ S[17+q] ^ S[2+r]

    vt = [fp ^ gp ^ rc[0],
          fq ^ gq ^ rc[1],
          fr ^ gr ^ rc[2],
          fs ^ gs ^ rc[3]]

    vt = multM(vt, T)
    vt = [Sbox[vt[i]] for i in range(4)]
    vt = multM(vt, T)

    return vt

def F(S, rn):
    for i in range(rn):
        vt = computeT(S)
        for j in range(81):
            S[j] = S[j+1]
        S[q-1] = vt[0]
        S[r-1] = vt[1]
        S[s-1] = vt[2]
        S[81] = vt[3]

def init(S, key, IV):
    for i in range(32):
        S[i] = key[i]
    for j in range(32):
        S[i+32] = IV[i]
    for i in range(16):
        S[i+64] = key[i] ^ 15
    S[80] = 15
    S[81] = 14

def encrypt(key, IV, pt):
    init(state, key, IV)
    F(state, 100)
    ct = []
    for i in range(len(pt)):
        block = [0] * 16
        for j in range(4):
            block[j] = state[15 + j] = state[15 + j] ^ pt[i][j]
            block[j + 4] = state[16 + q + j] = state[16 + q + j] ^ pt[i][j + 4]
            block[j + 8] = state[17 + r + j] = state[17 + r + j] ^ pt[i][j + 8]
            block[j + 12] = state[18 + s + j] = state[18 + s + j] ^ pt[i][j + 12]
        ct.append(block)
        F(state, 4)
    return ct

if __name__ == '__main__':
    key = [random.randint(0, 15) for _ in range(32)]
    IV = [random.randint(0, 15) for _ in range(32)]
    pt = [[random.randint(0, 15) for _ in range(16)] for _ in range(5)]
    ct = encrypt(key, IV, pt)
    print(pt)
    print(ct)
    flag = 'EOF{' + hashlib.sha256(''.join('{:01x}'.format(x) for x in key).encode()).hexdigest() + '}'
    # print(flag)
