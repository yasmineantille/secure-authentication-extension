"""
Proof of correctness of the scheme in python
Dependency of tinyec library -> Install with: pip install tinyec
"""
from helper import mod_inverse
import tinyec.registry as reg
import secrets


class SecureAuthenticationPoC:
    """
    This class implements the scheme using the python tinyec library
    """

    def __init__(self):
        self.curve = reg.get_curve('secp256r1')  # Set the ecc curve
        self.msk = {}
        self.secret_key = {}
        self.range = self.curve.field.n     # modulus will be the order of the curve

    def setup(self):
        """
        Setup msk := (k, r)
        """
        print("\nSetup!")
        k = []
        r = []
        for i in range(5):
            # Generate private keys for k, r
            k.append(secrets.randbelow(self.range))
            r.append(secrets.randbelow(self.range))
        print("k values: ", k)
        print("r values: ", r)
        self.msk = {"k": k, "r": r}

    def key_derivation(self, y):
        """
        Key derivation sk_y = (k_y, y_bar)
        k_y = sum k_i*y_i (mod n)
        y_bar_i = r_i*y_i (mod n)
        """
        print("\nKey Derivation!")
        k_y = 0
        y_bar = []
        for i in range(5):
            # k_i * y_i
            k_y += (self.msk.get("k")[i] * y[i]) % self.range

            # r_i * y_i
            y_bar_i = (self.msk.get("r")[i] * y[i]) % self.range
            y_bar.append(y_bar_i)

        k_y = k_y % self.range  # final mod for sum
        print("k_y value: ", k_y)
        print("y_bar values: ", y_bar)
        self.secret_key = {"k_y": k_y, "y_bar": y_bar}

    def encryption(self, z):
        """
        Encryption ct := (c, g)
        g is random point on curve
        c_i = (g*z_i + g*k_i) * r_i⁻¹
        """
        print("\nEncryption!")

        g = self.generate_random_g()

        ciphertext = []
        for i in range(5):
            # g * z_i
            g_zi = g * z[i]

            # g * k_i
            g_ki = g * self.msk.get("k")[i]
            tmp_sum = g_zi + g_ki

            # mod inverse of r
            # mod_inv_r_i = pow(self.msk.get("r")[i], -1, self.range)
            mod_inv_r_i = mod_inverse(self.msk.get("r")[i], self.range)
            ciphertext.append(tmp_sum * mod_inv_r_i)

        print("Ciphertext points: ")
        for cipher in ciphertext:
            print(cipher)
        return g, ciphertext

    def decryption(self, ciphertext, g):
        """
        Decryption d = (sum c_i * y_i ) - g*k_y
        """
        print("\nDecryption!")
        # set sum to first element multiplication
        sum = ciphertext[0] * self.secret_key.get("y_bar")[0]
        for i in range(1, 5):
            # c_i * y_bar_i
            tmp = ciphertext[i] * self.secret_key.get("y_bar")[i]
            sum += tmp

        # g * k_y
        g_k_y = g * self.secret_key.get("k_y")

        # sum - g_k_y
        decryption = sum - g_k_y
        print("Decrypted secret: ", decryption)
        return decryption

    @staticmethod
    def test(x, value) -> bool:
        """
        Test method for verification
        g * <y, y'>
        g = x
        value is the inner product for scalar mult
        """
        result = x * value
        print("Test result: ", result)
        return result

    def generate_random_g(self):
        # generate random g
        priv_key = secrets.randbelow(self.range)
        g = priv_key * self.curve.g
        print("Point g for encryption: ", g)
        return g


# Go through proof of correctness
scheme = SecureAuthenticationPoC()

# Step 1) Call setup
scheme.setup()

# Step 2) Call key derivation with reference template b
b = [2, 2, 2, 2, 2]
# b = [2, 3, 4, 5, 6]   # ip would be 90
scheme.key_derivation(b)

# Step 3) Encrypt z, where z equals b
x, c = scheme.encryption(b)

# Step 4) Decrypt ciphertext
decrypted_secret = scheme.decryption(c, x)

# Step 5) Control test
ip = 20  # inner product of y and z
test_result = scheme.test(x, ip)

# See that expected result equals the decrypted result for same reference template
assert decrypted_secret == test_result
