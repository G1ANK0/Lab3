
import requests
import struct
from Task_1_mine import sha_256
from urllib.parse import unquote_plus, quote

comment = "comment%3Dyou+don%27t+need+more+than+128+bits+of+symmetric+keys+for+post-quantum+security" 
tag = "4a621734dc9558649a185a8f83d598159407391ce942e29cf11617ed83d5afeb"

# The key is probably 16 bytes (128 bits), 
# block 1: 16 (key) + 16 (msg pt 1), block 2: 32 (msg pt 2), block 3: 32 (msg pt 3), block 4: 5 (msg pt final) + 27 (glue padding)

comment_bytes = unquote_plus(comment).encode("UTF-8")
comment_len = len(comment_bytes) # 85 bytes
key_length = 16

message_length = key_length + comment_len # 101 bytes
message_bits_length = message_length * 8 # 808 bits

# The padding is: 0x80 + 0x00*18 + 8 bytes of message length (in bits) big endian (the dx-est bits are used)
padding = (b'\x80' + b'\x00'*18 + struct.pack('>Q', message_bits_length))
print(padding)
extension = b';admin=true'



new_tag = sha_256(extension, 128, bytes.fromhex(tag))

print(new_tag)


url = "https://interrato.dev/infosec/lengthextension?cookie=" + comment + quote(padding) + quote(extension) + "&tag=" + quote(new_tag)


response = requests.get(url)
if response.status_code == 200:
    print(response.text)    
else:
    print(f"Request failed with status code: {response.status_code}")



