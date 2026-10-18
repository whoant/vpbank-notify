fn main() {
    prost_build::compile_protos(
        &["src/proto/checkin.proto", "src/proto/mcs.proto"],
        &["src/proto"],
    )
    .expect("compile protobuf contracts");
}
