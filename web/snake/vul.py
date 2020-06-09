import os
import pickle
import sys
import base64

s = input(":")

print(pickle.loads(base64.b64decode(s)))
