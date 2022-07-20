# Certstream Server Go

Aims to be a drop in replacement for the [official certstream server](https://github.com/CaliDog/certstream-server/) by Calidog.

### Motivation
From the moment I first found out about the certificate transparency logs, I was absolutely amazed by the great software by Calidog who made the transparency log available for all kinds of users by parsing the log and providing it in a format that was easy to use: json.

After creating my first application that used the certstream server, I found that it wasn't as reliable as I thought it would be.
I got disconnects and sometimes other errors.
Reasons for this could be that it was being hosted behind cloudflare.

I thought about running my own instance of certstream, but I was kinda afraid of Elixir/Erlang.
Hence I wanted to provide a go version of the certstream server. Why Go? Because it is a great language that compiles to native binaries on all major architectures and OS.


