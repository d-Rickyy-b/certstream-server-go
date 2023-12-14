FROM alpine

WORKDIR /app

ENV USER=certstreamserver
ENV UID=10001

# Create user
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# Copy our static executable.
COPY certstream-server-go /app/certstream-server-go
COPY ./config.sample.yaml /app/config.yaml

# Use an unprivileged user.
USER certstreamserver:certstreamserver

EXPOSE 8080

ENTRYPOINT ["/app/certstream-server-go"]