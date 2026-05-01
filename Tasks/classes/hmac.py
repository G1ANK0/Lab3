import hashlib

from utils.utils import xor

class HMAC:
    """
    Class that implements HMAC according to FIPS 198-1
    """
    def __init__(self, key: bytes, msg: bytes, hash_fun: str) -> None:
        self.__key: bytearray = bytearray(key)
        self.__msg: bytearray = bytearray(msg)

        self.__hash_fun = hashlib.new(hash_fun)

        self.__B: int = self.__hash_fun.block_size
        self.__L: int = self.__hash_fun.digest_size

        self.__ipad: bytearray = bytearray([0x36] * self.__B)
        self.__opad: bytearray = bytearray([0x5c] * self.__B)

    def update(self, msg: bytes) -> None:
        """
        Change the message to be hashed

        :param msg: message to be hashed
        """
        self.__msg = bytearray(msg)

    def __init_k0(self) -> bytearray:
        """
        Initialization of the key k0 according to FIPS 198-1: step 1-3 if the algorithm)
        :return:
        """
        if len(self.__key) == self.__B:
            return bytearray(self.__key)
        elif len(self.__key) > self.__B:
            h = hashlib.new(self.__hash_fun.name)
            h.update(self.__key)

            return bytearray(h.digest().ljust(self.__B, b'\x00'))
        else:
            return bytearray(self.__key).ljust(self.__B, b'\x00')

    def digest(self) -> bytes:
        """
        Compute the digest of the message according to FIPS 198-1: step 4-9

        :return: digest of the message in bytes
        """
        k_0 = self.__init_k0()

        xor_ipad = xor(k_0, self.__ipad)

        h_inner = hashlib.new(self.__hash_fun.name)
        h_inner.update(xor_ipad + self.__msg)
        inner = h_inner.digest()

        xor_opad = xor(k_0, self.__opad)

        h_outer = hashlib.new(self.__hash_fun.name)
        h_outer.update(xor_opad + inner)

        return h_outer.digest()