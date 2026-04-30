
import requests
from Task_1 import sha256
from urllib.parse import unquote_plus, quote

comment = "comment%3Dyou+don%27t+need+more+than+128+bits+of+symmetric+keys+for+post-quantum+security" 
tag = "4a621734dc9558649a185a8f83d598159407391ce942e29cf11617ed83d5afeb"
print(type(tag))

# 85 bytes -> 85 mod (32) = 21, I get two full blocks + 21 bytes. The key is probably 16 bytes (128 bits), thus get
# block 1: 16 (key) + 16 (msg pt 1), block 2: 32 (msg pt 2), block 3: 32 (msg pt 3), block 4: 5 (msg pt final) + 27 (glue padding)
comment_bytes = unquote_plus(comment).encode("UTF-8")
print(len(comment_bytes))

padding = (b'\x80' + b'\x00'*26)
user_type = "admin=true"
msg = padding + user_type.encode()
tag_list = [tag[i:i+8].encode() for i in range(0, len(tag),8)]


print(tag_list)
new_tag = sha256(msg, 128, tag_list)




url = "https://interrato.dev/infosec/lengthextension?cookie=" + comment + quote(padding + user_type) + "&tag=" + quote(new_tag)
response = requests.get(url)
print(response)



