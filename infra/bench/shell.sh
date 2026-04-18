# shellcheck shell=bash
bench_shell() {
  exec docker compose run --rm \
    -e ANDROID_ADB_SERVER_ADDRESS=cuttlefish \
    -e ANDROID_ADB_SERVER_PORT=5037 \
    -e ADB_DEVICE_SERIAL=0.0.0.0:6520 \
    -e FRIDA_HOST=cuttlefish \
    -e FRIDA_PORT=27042 \
    agent bash
}
