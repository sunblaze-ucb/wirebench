FROM us-docker.pkg.dev/android-cuttlefish-artifacts/cuttlefish-orchestration/cuttlefish-orchestration:stable

ARG CF_ARCH=arm64
ARG FRIDA_VERSION=17.9.1

# The upstream cuttlefish-orchestration image installs adb at
# /usr/lib/cuttlefish-common/bin/adb (from the cuttlefish-base apt package),
# but does not put it on PATH. Promote it so plain `adb` resolves to the
# version Google ships with this image.
ENV PATH=/usr/lib/cuttlefish-common/bin:$PATH

RUN apt-get update -qq \
    && apt-get install -y -qq curl xz-utils unzip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/frida \
    && curl -fsSL -o /tmp/frida-server.xz \
        "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${CF_ARCH}.xz" \
    && unxz -c /tmp/frida-server.xz > /opt/frida/frida-server \
    && chmod +x /opt/frida/frida-server \
    && rm /tmp/frida-server.xz

# Also download the matching 32-bit frida-server so we can hook armeabi-v7a
# (32-bit ARM) and x86 apps, which many Chinese-market APKs still ship as.
# The 32-bit counterpart to arm64 is "arm"; to x86_64 is "x86".
RUN case "${CF_ARCH}" in \
        arm64)  FRIDA_ARCH_32=arm ;; \
        x86_64) FRIDA_ARCH_32=x86 ;; \
        *)      FRIDA_ARCH_32="" ;; \
    esac \
    && if [ -n "${FRIDA_ARCH_32}" ]; then \
         curl -fsSL -o /tmp/frida-server-32.xz \
            "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH_32}.xz" \
         && unxz -c /tmp/frida-server-32.xz > /opt/frida/frida-server-32 \
         && chmod +x /opt/frida/frida-server-32 \
         && rm /tmp/frida-server-32.xz; \
       fi

COPY entrypoint.sh /usr/local/bin/wirewatch-entrypoint.sh
RUN chmod +x /usr/local/bin/wirewatch-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/wirewatch-entrypoint.sh"]
