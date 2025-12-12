fn main() {
    prost_build::compile_protos(&["proto/cortex.proto"], &["proto"]).unwrap();
    tauri_build::build()
}
