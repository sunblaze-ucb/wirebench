FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update -qq && \
    apt-get install -y -qq \
        sudo git python3 python3-pip curl wget unzip \
        openjdk-17-jre-headless binutils file tshark \
        build-essential gcc g++ make pkg-config \
        ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 20.x ────────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y -qq nodejs && \
    rm -rf /var/lib/apt/lists/*

# ── jadx v1.5.5 ─────────────────────────────────────────────────────────────
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/* && \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm -f /tmp/jadx.zip

# ── apktool v2.10.0 ─────────────────────────────────────────────────────────
RUN wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar \
        -O /usr/local/bin/apktool.jar && \
    printf '#!/bin/sh\nexec java -jar /usr/local/bin/apktool.jar "$@"\n' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# ── radare2 5.9.8 + r2ghidra (Ghidra decompiler plugin → `pdg` command) ──────
RUN apt-get update -qq && apt-get install -y -qq cmake && rm -rf /var/lib/apt/lists/* && \
    git clone --depth 1 --branch 5.9.8 https://github.com/radareorg/radare2.git /opt/radare2-src && \
    cd /opt/radare2-src && sys/install.sh && \
    r2pm -U && r2pm -ci r2ghidra

# ── Python packages ──────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir pycryptodome r2pipe lief pyelftools tomli boto3 frida-tools==14.8.1

# ── ADB client (no server — agent talks to remote adb server in cuttlefish) ──
RUN apt-get update -qq && \
    apt-get install -y -qq android-tools-adb && \
    rm -rf /var/lib/apt/lists/*

# ── Claude Code (npm) ────────────────────────────────────────────────────────
RUN npm install -g @anthropic-ai/claude-code

# ── Agent user ───────────────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash agent && \
    echo 'agent ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && \
    usermod -aG wireshark agent 2>/dev/null || true

# ── Workspace directories ───────────────────────────────────────────────────
RUN mkdir -p /apk /traces /analysis /metadata /output /src /work /out && \
    chown -R agent:agent /apk /traces /analysis /metadata /output /src /work /out

CMD ["tail", "-f", "/dev/null"]
