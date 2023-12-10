![certstream-server-go logo](https://github.com/d-Rickyy-b/certstream-server-go/blob/master/docs/img/certstream-server-go_logo.png?raw=true)

# Certstream Server Go

[![build](https://github.com/d-Rickyy-b/certstream-server-go/actions/workflows/release_build.yml/badge.svg)](https://github.com/d-Rickyy-b/certstream-server-go/actions/workflows/release_build.yml)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/0rickyy0/certstream-server-go?label=docker&sort=semver)](https://hub.docker.com/repository/docker/0rickyy0/certstream-server-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/d-Rickyy-b/certstream-server-go.svg)](https://pkg.go.dev/github.com/d-Rickyy-b/certstream-server-go)

This project aims to be a drop-in replacement for the [certstream server](https://github.com/CaliDog/certstream-server/) by Calidog. This tool aggregates, parses, and streams certificate data from multiple [certificate transparency logs](https://www.certificate-transparency.org/what-is-ct) via websocket connections to the clients.

Everyone can use this project to analyze newly created TLS certificates as they are issued.

## Motivation

From the moment I first found out about the certificate transparency logs, I was absolutely amazed by the great software of [Calidog](https://github.com/CaliDog/), which made the transparency log easier accessible for everyone. 
Their software "Certstream" parses the log and provides it in an easy-to-use format: json.

After creating my first application that utilized the certstream server, I found that the hosted (demo) version of the server wasn't as reliable as I thought it would be. 
I got disconnects and sometimes other errors. Eventually the provided server was still only thought to be **a demo**.

I quickly thought about running my own instance of certstream. But I didn't want to install Elixir/Erlang on my server. Sure, I could have used Docker, but on second thought, I was really into the idea of creating an alternative server written in Go.

"Why Go?", you might ask. Because it is a great language that compiles to native binaries on all major architectures and OSes. All the cool kids are using it right now.

## Getting started

Setting up an instance of the certstream server is simple. You can either download and compile the code yourself, or use one of the [precompiled binaries](https://github.com/d-Rickyy-b/certstream-server-go/releases).

### Docker

There's also a prebuilt [Docker image](https://hub.docker.com/repository/docker/0rickyy0/certstream-server-go) available.
You can use it by running this command:

`docker run -d -v /path/to/config.yaml:/app/config.yaml -p 8080:8080 0rickyy0/certstream-server-go`

> ⚠️ If you don't mount your own config file, the default config (config.sample.yaml) will be used. For more details, check out the [wiki](https://github.com/d-Rickyy-b/certstream-server-go/wiki/Configuration).

## Connecting

certstream-server-go offers multiple endpoints to connect to.

| Config             | Default         | Function                                                                                  |
|--------------------|-----------------|-------------------------------------------------------------------------------------------|
| `full_url`         | `/full-stream`  | Constant stream of new certificates with all details available                            |
| `lite_url`         | `/`             | Constant stream of new certificates with reduced details (no `as_der` and `chain` fields) |
| `domains_only_url` | `/domains-only` | Constant stream of domains found in new certificates                                      |

You can connect to the certstream-server by opening a **websocket connection** to any of the aforementioned endpoints.
After you're connected, certificate information will be streamed to your websocket.

The server requires you to send a **ping message** at least every 60 seconds (it's recommended to use an interval of 30s for pings). 
If the server does not receive a ping message for more than this time, it will disconnect you. 
The server will **not** send out ping messages to your client.

Read more about ping/pong WebSocket messages in the [Mozilla Developer Docs](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#pings_and_pongs_the_heartbeat_of_websockets).

### Performance

At idle (no clients connected), the server uses about **40 MB** of RAM, **14.5 Mbit/s** and **4-10% CPU** (Oracle Free Tier) on average while processing around **250-300 certificates per second**.

### Monitoring

**certstream-server-go** also offers a Prometheus metrics endpoint at `/metrics`. You can use this to monitor the server with Prometheus and Grafana.
For an in-depth guide on how to do this, please refer to the [wiki](https://github.com/d-Rickyy-b/certstream-server-go/wiki/Collecting-and-Visualizing-Metrics).

![grafana dashboard](https://user-images.githubusercontent.com/5798157/211434271-4350766d-2942-4fcb-8fda-f131f3f61cea.png)

### Example

To receive a live example for any of the endpoints, just send an HTTP GET request to the endpoints with `/example.json` appended to the endpoint. 
For example: `/full-stream/example.json`. This shows the lite format of a certificate update.

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
            "sha1": "27:58:3D:01:3D:71:B8:D3:A6:6E:2C:7A:86:3A:E9:1F:DB:F0:1B:5D",
            "sha256": "57:61:38:C0:3C:03:A3:34:6A:0B:32:89:11:1B:74:AB:8A:DF:A5:02:9F:06:43:E6:F3:0E:69:F3:0E:4E:4E:FC",
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
