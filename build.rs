fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    embed_windows_icon();
}

#[cfg(target_os = "windows")]
fn embed_windows_icon() {
    let out_dir  = std::env::var("OUT_DIR").expect("OUT_DIR");
    let ico_path = std::path::Path::new(&out_dir).join("logo.ico");

    let src = image::open("logo.png").expect("logo.png not found");

    let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [256u32, 128, 64, 48, 32, 16] {
        let resized   = src.resize_exact(size, size, image::imageops::FilterType::Lanczos3).to_rgba8();
        let icon_img  = ico::IconImage::from_rgba_data(size, size, resized.into_raw());
        let entry     = ico::IconDirEntry::encode(&icon_img).expect("ico encode");
        dir.add_entry(entry);
    }

    let file = std::fs::File::create(&ico_path).expect("create logo.ico");
    dir.write(file).expect("write logo.ico");

    let mut res = winres::WindowsResource::new();
    res.set_icon(ico_path.to_str().unwrap());
    res.set("ProductName",     "Rustman");
    res.set("FileDescription", "Rustman — MITM Proxy & Web Security Tool");
    res.compile().expect("winres compile");
}

#[cfg(not(target_os = "windows"))]
fn embed_windows_icon() {}
