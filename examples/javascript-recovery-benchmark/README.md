# Owned recovery input

These files are copied byte for byte from the already retained native proof fixture, originally authored in tests/test_integration.py. They are an unwrapped JavaScript module and a version 3 source map with one sourcesContent entry. They are not Preact or a representative production bundle.

- entry.mjs SHA-256: 455a7c38956e7387d0362ecabcd0ba5e90f5e1e085568a98f5dc2df5c82f75bc
- entry.mjs.map SHA-256: 7d29f25a427c3fe95dab510a865670ccfb8553e1d3827ada45ca253c0d48f9df

The benchmark preparation script stages bundle-only and map-only copies separately. It does not execute this JavaScript or any external recovery tool. Results from the owned smoke fixture cannot rank Preact recovery quality.
