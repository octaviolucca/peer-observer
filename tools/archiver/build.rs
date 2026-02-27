use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("failed to run git rev-parse HEAD");

    let hash = String::from_utf8(output.stdout).unwrap();
    let hash = hash.trim();

    let b0 = u8::from_str_radix(&hash[0..2], 16).unwrap();
    let b1 = u8::from_str_radix(&hash[2..4], 16).unwrap();
    let b2 = u8::from_str_radix(&hash[4..6], 16).unwrap();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(&out_dir).join("git_hash.rs");
    std::fs::write(
        path,
        format!(
            "const GIT_HASH: [u8; 3] = [0x{:02x}, 0x{:02x}, 0x{:02x}];\n",
            b0, b1, b2
        ),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
