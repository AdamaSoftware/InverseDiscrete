from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha512
from secrets import randbelow as randint
from secrets import token_bytes

m = 10149176142605696715050247890886518684869103063509537620648493592653337479126199564779492324587095488340968978086015701129456592142832211053079944961964657
phi_m = 10149176142605696715050247890886518684869103063509537620648493592653337479125996503442675300056368522775758150165989588230953032145289349735940133307374080
g = 7591750238283022226591624292439856861266114590948725596089923869315745586749399736727671118946044001928889845078615515383621527746449037726675666424737183
y = 2891056567964536419792226341900413927324947280774856569161137065304101982988190331398099565097205452998393309058780684180528268411016489168811183745218800

def keygen():
    sk = randint(phi_m - 3) + 2
    P_A = pow(g, sk, m)
    pk = pow(P_A, y, m)
    return pk, sk

def hash(data):
    return int.from_bytes(sha512(data).digest())

def sign(sk, msg):
    r = randint(phi_m - 1) + 1
    t = pow(g, r*y, m)
    e = hash(msg + t.to_bytes((t.bit_length() + 7) // 8, 'big')) % phi_m
    s = (r + e * sk) % phi_m
    return (t, s)

def verify(pk, msg, signature):
    t, s = signature
    e = hash(msg + t.to_bytes((t.bit_length() + 7) // 8, 'big')) % phi_m
    lhs = pow(g, s*y, m)
    rhs = (t * pow(pk, e, m)) % m
    return lhs == rhs

