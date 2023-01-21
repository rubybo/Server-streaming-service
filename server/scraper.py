import requests


res = requests.get("http://localhost:5000/api/hw")


print(res.json())