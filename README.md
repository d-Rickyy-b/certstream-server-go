![certstream-server-go logo](https://github.com/d-Rickyy-b/certstream-server-go/blob/master/docs/img/certstream-server-go_logo.png?raw=true)

# Certstream Server Go
[![build](https://github.com/d-Rickyy-b/certstream-server-go/actions/workflows/release_build.yml/badge.svg)](https://github.com/d-Rickyy-b/certstream-server-go/actions/workflows/release_build.yml)
![Docker Image Version (latest semver)](https://img.shields.io/docker/v/0rickyy0/certstream-server-go?label=docker&sort=semver)

This project aims to be a drop-in replacement for the [official certstream server](https://github.com/CaliDog/certstream-server/) by Calidog. This tool aggregates, parses, and streams certificate data from multiple [certificate transparency logs](https://www.certificate-transparency.org/what-is-ct) via websocket connections to the clients.

Developers can use this project to analyze newly created TLS certificates as they are issued.

## Motivation
From the moment I first found out about the certificate transparency logs, I was absolutely amazed by the great software of [Calidog](https://github.com/CaliDog/) who made the transparency log easier accessible for everyone. Their software "Certstream" parses the log and provides it in an easy-to-use format: json.

After creating my first application that utilized the certstream server, I found that the hosted (demo) version of the server wasn't as reliable as I thought it would be. I got disconnects and sometimes other errors. Eventually the provided server was still only thought to be **a demo**.

I quickly thought about running my own instance of certstream. I didn't want to install Elixir/Erlang on my server. I could have used Docker, but on second thought, I was really into the idea of creating an alternative server, written in Go.

"Why Go?", you might ask. Because it is a great language that compiles to native binaries on all major architectures and OS. All the cool kids are using it right now.

## Getting started
Setting up an instance of the certstream server is simple. You can either download and compile the code by yourself or use one of our [precompiled binaries](https://github.com/d-Rickyy-b/certstream-server-go/releases).

### Docker
There's also a prebuild [Docker image](https://hub.docker.com/repository/docker/0rickyy0/certstream-server-go) available.
You can use it by running this command: 

`docker run -v /path/to/config.yaml:/app/config.yaml -p 8080:8080 0rickyy0/certstream-server-go -d`

If you don't mount your own config file, the default config (config.sample.yaml) will be used.

## Connecting
certstream-server-go offers multiple endpoints to connect to.

| Config             | Default         | Function                                                                                  |
|--------------------|-----------------|-------------------------------------------------------------------------------------------|
| `full_url`         | `/full-stream`  | Constant stream of new certificates with all details available                            |
| `lite_url`         | `/`             | Constant stream of new certificates with reduced details (no `as_der` and `chain` fields) |
| `domains_only_url` | `/domains-only` | Constant stream of domains found in new certificates                                      |

You can connect to the certstream-server by opening a **websocket connection** to any of the aforementioned endpoints.
After you're connected, certificate information will be streamed to your websocket.

The server requires you to send a ping message at least every `ping_interval` seconds. If the server did not receive a ping message for `ping_interval` seconds, the server will disconnect you. The server will **not** send out ping messages to your client.  
 
### Example
To receive a live example of any of the endpoints, just send a HTTP GET request to the endpoints with `/example.json` appended to the endpoint. So for example `/full-stream/example.json`. This example shows the lite format of a certificate update.

```json
{
    "data": {
        "cert_index": 712420366,
        "cert_link": "https://yeti2022-2.ct.digicert.com/log/ct/v1/get-entries?start=712420366&end=712420366",
        "leaf_cert": {
            "all_domains": [
                "cmslieferhit.e06.k-k.de"
            ],
            "extensions": {
                "authorityInfoAccess": "URI:http://r3.i.lencr.org/, URI:http://r3.o.lencr.org",
                "authorityKeyIdentifier": "keyid:14:2e:b3:17:b7:58:56:cb:ae:50:09:40:e6:1f:af:9d:8b:14:c2:c6",
                "basicConstraints": "CA:FALSE",
                "keyUsage": "Digital Signature, Key Encipherment",
                "subjectAltName": "DNS:cmslieferhit.e06.k-k.de",
                "subjectKeyIdentifier": "keyid:4e:cb:ae:47:84:a8:92:f7:e7:de:78:d1:00:9e:d9:cc:80:ac:0b:ce"
            },
            "fingerprint": "27:58:3D:01:3D:71:B8:D3:A6:6E:2C:7A:86:3A:E9:1F:DB:F0:1B:5D",
            "not_after": 1667028404,
            "not_before": 1659252405,
            "serial_number": "0498BDF812FAF923FEBD5EF7B374899FC61A",
            "signature_algorithm": "sha256, rsa",
            "subject": {
                "C": null,
                "CN": "cmslieferhit.e06.k-k.de",
                "L": null,
                "O": null,
                "OU": null,
                "ST": null,
                "aggregated": "/CN=cmslieferhit.e06.k-k.de",
                "email_address": null
            },
            "issuer": {
                "C": "US",
                "CN": "R3",
                "L": null,
                "O": "Let's Encrypt",
                "OU": null,
                "ST": null,
                "aggregated": "/C=US/CN=R3/O=Let's Encrypt",
                "email_address": null
            },
            "is_ca": false
        },
        "seen": 1659301203.904,
        "source": {
            "name": "DigiCert Yeti2022-2 Log",
            "url": "https://yeti2022-2.ct.digicert.com/log"
        },
        "update_type": "PrecertLogEntry"
    },
    "message_type": "certificate_update"
}
```

