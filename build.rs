//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    let protos = [
        "src/attest/proto/cds2.proto",
        "src/attest/proto/svr.proto",
        "src/attest/proto/svr2.proto",
        "src/attest/proto/svr3.proto",
        "src/net/proto/chat_websocket.proto", 
        "src/net/proto/cds2.proto",
        "src/svr3/proto/svr3.proto",
    ];
    prost_build::compile_protos(&protos, &["src"]).expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
