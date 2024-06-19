#[cfg(target_os = "macos")]
mod macos {
    #[derive(serde::Deserialize)]
    pub(super) struct Cargo {
        pub(super) package: CargoPackage,
    }

    #[derive(serde::Deserialize)]
    pub(super) struct CargoPackage {
        pub(super) metadata: CargoPackageMetadata,
    }

    #[derive(serde::Deserialize)]
    pub(super) struct CargoPackageMetadata {
        pub(super) bundle: CargoPackageMetadataBundle,
    }

    #[derive(serde::Deserialize)]
    pub(super) struct CargoPackageMetadataBundle {
        pub(super) identifier: String,
    }

    #[derive(serde::Deserialize)]
    pub(super) struct SwiftTarget {
        pub(super) target: SwiftTargetInfo,
        pub(super) paths: SwiftPaths,
    }

    #[derive(serde::Deserialize)]
    pub(super) struct SwiftTargetInfo {
        #[serde(rename = "unversionedTriple")]
        pub(super) unversioned_triple: String,
    }

    #[derive(serde::Deserialize)]
    pub(super) struct SwiftPaths {
        #[serde(rename = "runtimeLibraryPaths")]
        pub(super) runtime_library_paths: Vec<String>,
    }
}
#[cfg(target_os = "macos")]
use macos::*;

fn main() {
    #[cfg(target_os = "macos")]
    {
        update_identifier();
        link_swift();
        link_swift_package("macos_native", "./macos_native/");
    }
}

#[cfg(target_os = "macos")]
fn update_identifier() {
    let content = std::fs::read_to_string("Cargo.toml").unwrap();
    let cargo: Cargo = toml::from_str(&content).unwrap();
    std::fs::write("identifier.txt", cargo.package.metadata.bundle.identifier).unwrap();
}

#[cfg(target_os = "macos")]
fn link_swift() {
    let swift_target_info = get_swift_target_info();
    swift_target_info.paths.runtime_library_paths.iter().for_each(|path| {
        println!("cargo:rustc-link-search=native={}", path);
    });
}

#[cfg(target_os = "macos")]
fn link_swift_package(package_name: &str, package_root: &str) {
    let profile = std::env::var("PROFILE").unwrap();
    if !std::process::Command::new("swift")
        .args(["build", "-c", &profile])
        .current_dir(package_root)
        .status()
        .unwrap()
        .success()
    {
        panic!("Failed to compile swift package {}", package_name);
    }
    let swift_target_info = get_swift_target_info();
    println!(
        "cargo:rustc-link-search=native={}.build/{}/{}",
        package_root, swift_target_info.target.unversioned_triple, profile
    );
    println!("cargo:rustc-link-lib=static={}", package_name);
}

#[cfg(target_os = "macos")]
fn get_swift_target_info() -> SwiftTarget {
    let swift_target_info_str =
        std::process::Command::new("swift").args(["-print-target-info"]).output().unwrap().stdout;
    serde_json::from_slice(&swift_target_info_str).unwrap()
}
