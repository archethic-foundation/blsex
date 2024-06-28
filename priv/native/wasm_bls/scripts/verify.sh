#!/bin/sh

extism call target/wasm32-unknown-unknown/debug/wasm_bls.wasm verifySignature --input \
"{\"signature\": \"ad95489865d4b502f3d0d265541bef07cae685ddffd5b743ace24bf8e110375389e389f1c950acde77268f18d77da34c0f7c05b4ce2de60300641cf77ecde9c3b3a75d811d1f345dd87cb3f9b155f7f8283d8b60b28229a9d5a32343fb96b165\", \"data\": \"hello\", \"public_key\": \"82e790438e433df65dcd9e8d0e7f30f23782a3131924fb05a7b5037a695adf1ad34de35713d454e76a756a6ce787e221\"}"
