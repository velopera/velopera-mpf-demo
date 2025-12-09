# velopera-mpf-demo: NRF transport fuzzer demo

This demo shows how to compile and run the NRF transport fuzzer against the `velopera-nrf-firmware` components.

## Build

```bash
./afl-gcc -o nrf_transport_fuzzer nrf_transport_fuzzer.c
```

## Test with valid inputs

```bash
./nrf_transport_fuzzer velopera-nrf-inputs mqtt_payload.bin
./nrf_transport_fuzzer velopera-nrf-inputs mqtt_topic.bin
./nrf_transport_fuzzer velopera-nrf-inputs gps_data.bin
```

## Test with crashable binaries

```bash
./nrf_transport_fuzzer velopera-nrf-crash-inputs mqtt_crash.bin
# ... add other crash-inducing binaries similarly
```

## Fuzzing

Run AFL with the provided seed corpus:

```bash
afl-fuzz -i velopera-nrf-inputs -o nrf_results -m none -- ./nrf_transport_fuzzer @@
```

Notes:
- Ensure AFL is installed and available in your PATH. On Linux, you may need to allow core dumps and set appropriate limits for AFL.
