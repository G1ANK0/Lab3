class MerkleDamgardHash:
    """
    Abstract base for Merkle-Damgård hash functions.
    Subclasses must define:
      - BLOCK_SIZE      : int   (bytes per block, e.g. 64 or 128)
      - DIGEST_SIZE     : int   (bytes of output, e.g. 32 for SHA-256)
      - _INITIAL_STATE  : list  (initial hash values)
      - _compress()     : compress one block into the running state
      - _pack_state()   : serialize state words to bytes (before truncation)
    """

    BLOCK_SIZE  : int = NotImplemented
    DIGEST_SIZE : int = NotImplemented
    _INITIAL_STATE : list = NotImplemented

    def __init__(self, data: bytes = b""):
        self._state     = list(self._INITIAL_STATE)
        self._buffer    = b""           # unprocessed bytes
        self._msg_len   = 0             # total bytes fed so far

        if data:
            self.update(data)

    def update(self, data: bytes) -> "MerkleDamgardHash":
        """Feed more data into the hash. Returns self for chaining."""
        self._buffer  += data
        self._msg_len += len(data)

        while len(self._buffer) >= self.BLOCK_SIZE:
            self._state  = self._compress(self._state, self._buffer[:self.BLOCK_SIZE])
            self._buffer = self._buffer[self.BLOCK_SIZE:]

        return self

    def set_state(self, new_state: str) -> None:
        step_size = 2 * self.DIGEST_SIZE // 8

        self._state = [int(new_state[i : i+step_size], 16) for i in range(0, 2 * self.DIGEST_SIZE, step_size)]

    def digest(self) -> bytes:
        """Return the final digest without modifying internal state."""
        # Work on a copy so digest() can be called multiple times
        state  = list(self._state)
        padded = self._pad(self._buffer, self._msg_len)

        for i in range(0, len(padded), self.BLOCK_SIZE):
            state = self._compress(state, padded[i:i + self.BLOCK_SIZE])

        return self._pack_state(state)[:self.DIGEST_SIZE]

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "MerkleDamgardHash":
        """Return a copy of the current state (for branching)."""
        clone = object.__new__(type(self))
        clone._state   = list(self._state)
        clone._buffer  = self._buffer
        clone._msg_len = self._msg_len
        return clone

    @classmethod
    def hash(cls, data: bytes) -> bytes:
        return cls(data).digest()

    @classmethod
    def hexhash(cls, data: bytes) -> str:
        return cls(data).hexdigest()

    def _pad(self, buffer: bytes, msg_len: int) -> bytes:
        raise NotImplementedError

    def _compress(self, state: list, block: bytes) -> list:
        raise NotImplementedError

    def _pack_state(self, state: list) -> bytes:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{type(self).__name__}(msg_len={self._msg_len})"