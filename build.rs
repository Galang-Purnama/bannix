fn main() {
    println!("cargo:rerun-if-changed=src/accel/fast_ip.c");
    println!("cargo:rerun-if-changed=src/accel/fast_ip.h");
    println!("cargo:rerun-if-changed=src/accel/netlink_raw.c");
    println!("cargo:rerun-if-changed=src/accel/netlink_raw.h");

    cc::Build::new()
        .file("src/accel/fast_ip.c")
        .file("src/accel/netlink_raw.c")
        .include("src/accel")
        .opt_level(3)
        .compile("bannix_c");
}

