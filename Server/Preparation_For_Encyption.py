# RSA algorithm. Main goal is to pass securely symmetrical keys between the server and the client so they can encrypt
# and decrypt properly and securely eachother.

from random import randrange, getrandbits
import time
Error_time = 1
Start_Public_E = 5


def is_prime(n, k=128):
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime_candidate(length):
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p


def generate_prime_number(length=9):  # was 1024
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


def RSA_server():  # Alice
    global PRIVATE_KEY, PUBLIC_KEY
    while True:
        q = generate_prime_number()
        p = generate_prime_number()
        n = p*q
        m = Euler_func(n)
        e = Start_Public_E
        for e in range(Start_Public_E, m):  # a number that's quite low
            if e % 2 != 0 and gcd(e, n) == 1:
                break
        PUBLIC_KEY = [str(e), str(n)]
        k = 1
        start_time = time.time()
        while time.time()-start_time < Error_time:
            d = try_private_key(k, m, e)
            if d.is_integer():
                PRIVATE_KEY = int(d)
                return
            k = k + 1


def Euler_func(n):  # how much numbers are lower and foreign to n == value of m
    amount = 0
    for k in range(1, n + 1):
        if gcd(n, k) == 1:
            amount += 1
    return amount


def gcd(a, b):  # is a foreign to b
    while b != 0:
        a, b = b, a % b
    return a


def try_private_key(k, m, e):  # if d is an int (not a float) then d is legal.
    d = (k * m + 1)/e
    return d


def get_public_key():  #  get the public key if available
    return PUBLIC_KEY


def get_symmetrical_key(msg_encode):
    blah = pow(msg_encode, PRIVATE_KEY)
    msg_decode = blah % int(get_public_key()[1])
    return msg_decode

