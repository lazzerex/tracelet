fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    libbpf_cargo::SkeletonBuilder::new()
        .source("src/bpf/tracelet.bpf.c")
        .reference_obj(true)
        .build_and_generate(format!("{out_dir}/tracelet.skel.rs"))
        .unwrap();
    println!("cargo:rerun-if-changed=src/bpf");
}
