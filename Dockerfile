# Build stage: plain gcc + libpcap headers.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev libpcap-dev ca-certificates curl ieee-data \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY src ./src
COPY tests ./tests
RUN make CFLAGS="-O2 -Wall -Wextra -Werror" && make check
# Vendor names: Debian's ieee-data package is the guaranteed copy; a fresher one is
# fetched from the IEEE if their site answers (it often doesn't), never failing the build.
RUN mkdir -p /oui && cp /usr/share/ieee-data/oui.csv /oui/oui.csv \
    && (curl -fsSL --max-time 20 --retry 2 -o /oui/oui.new https://standards-oui.ieee.org/oui/oui.csv \
        && [ "$(wc -c < /oui/oui.new)" -gt 1000000 ] && mv /oui/oui.new /oui/oui.csv && echo "OUI: live copy" \
        || echo "OUI: using Debian ieee-data copy")

# Runtime stage: just the binary, libpcap, and the OUI file.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/lan-devices /usr/local/bin/lan-devices
COPY --from=build /oui/oui.csv /usr/share/lan-devices/oui.csv
# Aliases, learned names and watch state persist here; mount a volume.
ENV LAN_DEVICES_DIR=/data
VOLUME /data
EXPOSE 9341
# Needs host networking (it must sit on the LAN's layer 2) and CAP_NET_RAW:
#   docker run --rm --network host --cap-drop ALL --cap-add NET_RAW -v lan-devices:/data ghcr.io/jacobsim0/lan-devices --watch
ENTRYPOINT ["/usr/local/bin/lan-devices"]
CMD ["--watch"]
