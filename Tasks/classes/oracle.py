import os
import hashlib

class SecretPrefixMACOracle:
    def __init__(self, key_len: int=16, hash_name: str="sha256") -> None:
        self.__key:  bytes= os.urandom(key_len)
        self.__hash_name: str = hash_name

    def __hash(self, data: bytes) -> bytes:
        h = hashlib.new(self.__hash_name)
        h.update(data)
        return h.digest()

    def __tag(self, message: bytes) -> bytes:
        return self.__hash(self.__key + message)

    def verify(self, message: bytes, tag: bytes) -> bool:
        """
        Oracle that checks if the tag is correct

        :param message: the message to be authenticated
        :param tag: input tag (computed by the client)

        :return: True if the tag is correct, False otherwise
        """
        return self.__tag(message) == tag