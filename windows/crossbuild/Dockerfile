FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV WINEDEBUG=-all
ENV WINEPREFIX=/wine

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        innoextract \
        p7zip-full \
        wine \
        wine64 \
        wine32:i386 \
        xauth \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

COPY compile-installer.sh /usr/local/bin/compile-installer.sh

RUN chmod +x /usr/local/bin/compile-installer.sh

ENTRYPOINT ["/usr/local/bin/compile-installer.sh"]
