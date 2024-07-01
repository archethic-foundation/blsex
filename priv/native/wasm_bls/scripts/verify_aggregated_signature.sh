#!/bin/sh

extism call target/wasm32-unknown-unknown/release/wasm_bls.wasm verifyAggregatedSignature \
--input "{\"signature\": \"94846c5c947cb38a23a8d2bccb3f2d6cc85f8a5e931b20919a6f38fea7f4d99007538dba19b16852eb9abfa450b4136d0331dc37d5fbe04253e58d79f264761e6bbe2ffc6fd4f070761e5b1b50654a8239f5902a5bd0e282bb0ec87e82298f5e\", \"data\": \"hello\", \"public_keys\": [\"82e790438e433df65dcd9e8d0e7f30f23782a3131924fb05a7b5037a695adf1ad34de35713d454e76a756a6ce787e221\", \"a3afba533dff8737e3602f1231871ba11224e11df92cb8bcf3cb66e9d311638103f308addb9562cb07bf6221bb0d3d00\"]}" \
--log-level=info
