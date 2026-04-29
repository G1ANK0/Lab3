
import requests
from Task_1 import sha256
from urllib.parse import unquote_plus, quote

comment = "comment%3Dyou+don%27t+need+more+than+128+bits+of+symmetric+keys+for+post-quantum+security" 
tag = "4a621734dc9558649a185a8f83d598159407391ce942e29cf11617ed83d5afeb"

# 85 bytes -> 85 mod (64) = 21, thus I need 64-21 = 43 byte to pad. The key is probably 16 bytes (128 bits), thus get
# block 1: 16 (key) + 48 (msg pt 1), block 2: 37 (msg pt 2)+ 27 (padding)
comment_bytes = unquote_plus(comment).encode("UTF-8")
print(len(comment_bytes))
url = "https://interrato.dev/infosec/lengthextension?cookie=comment%3Dyou+don%27t+need+more+than+128+bits+of+symmetric+keys+for+post-quantum+security&tag=4a621734dc9558649a185a8f83d598159407391ce942e29cf11617ed83d5afeb"

padding = (b'\x80' + b'\x00'*26)
user_type = "admin=true"
msg = padding + user_type.encode()

new_tag = sha256(msg, 128, tag.encode() )



url = "https://interrato.dev/infosec/lengthextension?cookie=" + comment + quote(padding + user_type) + "&tag=" + quote(new_tag)
response = requests.get(url)
print(response)



