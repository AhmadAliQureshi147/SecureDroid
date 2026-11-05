import pickle
import ssl
import requests

def load(blob, url):
    requests.get(url, verify=False)
    ssl._create_unverified_context()
    return pickle.loads(blob)
