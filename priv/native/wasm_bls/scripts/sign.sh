#!/bin/sh

extism call target/wasm32-unknown-unknown/release/wasm_bls.wasm signData --input "{\"seed\": \"B80C035591824036CC214F76B8A8A9A4D1DB1B0BADE6B6964660069D142A600A\",\"data\": \"hello\"}"
# ad95489865d4b502f3d0d265541bef07cae685ddffd5b743ace24bf8e110375389e389f1c950acde77268f18d77da34c0f7c05b4ce2de60300641cf77ecde9c3b3a75d811d1f345dd87cb3f9b155f7f8283d8b60b28229a9d5a32343fb96b165

extism call target/wasm32-unknown-unknown/release/wasm_bls.wasm signData --input "{ \"seed\": \"1D31933538B1CD8918BFF857BDD57AF80472D5B9C984D057FA9D0247FDEF2F08\", \"data\": \"hello\"}" --log-level=info
# b6df816b4e19c33e1978061a189650e8534f14b79fe30b8f8fd6ce3ba904e5f161a88918c65cdbea239120af752406ae03b35fa8fe77af125464d57aea75b5f00135e813ce8b921785d6368faf3492971432758c5ef81f500876a3de418332dd
