import random
from math import gcd as bltin_gcd

def generate_random(length=100):
    lower_bound = 10 ** (length-1)
    upper_bound = (10 ** length) - 1
    return random.randint(lower_bound, upper_bound)

def read_file(pathname):
    with open(pathname, 'r') as infile:
        return infile.read()

def miller_rabin_test(d, n):
    a = random.randint(2, n-2)
    x = pow(a, d, n)

    if(x == 1 or x == n-1):
        return True

    while(d != n - 1):
        x = pow(x, 2, n)
        d *= 2

        if(x == 1):
            return False
        if(x == n-1):
            return True

    return False

def is_prime(n, k=10):
    if (n <= 1 or n == 4): return False
    if (n < 3): return True

    d = n - 1
    while(d % 2 == 0): d //= 2

    for i in range(k):
        if(not miller_rabin_test(d, n)): return False

    return True

# return gcd, x, y that satisfied ax + by = 1
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

class RSA(object):
    def generate_prime(self, length):
        p = generate_random(length)
        while (not is_prime(p)):
            p = generate_random(length)
        return p

    def generate_keys(self, p, q):
        n = p * q
        totient = (p-1)*(q-1)
        e = 2
        while(bltin_gcd(e, totient) != 1):
            e += 1
        print("totient = {}  e = {}".format(totient, e))

        d = modinv(e, totient)
        print("d = ", d)

        return (e, n), (d, n)


if __name__ == "__main__":
    rsa = RSA()
    p = rsa.generate_prime(length=2)
    q = rsa.generate_prime(length=2)
    print("Prime number 1 = ", p)
    print("Prime number 2 = ", q)

    public_keys, private_keys = rsa.generate_keys(p, q)