#[cfg(all(target_os = "macos", feature = "notifications"))]
mod macos {
    #[derive(serde::Deserialize)]
    struct Cargo {
        package: CargoPackage,
    }

    #[derive(serde::Deserialize)]
    struct CargoPackage {
        metadata: CargoPackageMetadata,
    }

    #[derive(serde::Deserialize)]
    struct CargoPackageMetadata {
        bundle: CargoPackageMetadataBundle,
    }

    #[derive(serde::Deserialize)]
    struct CargoPackageMetadataBundle {
        identifier: String,
    }

    #[derive(serde::Deserialize)]
    struct SwiftTarget {
        target: SwiftTargetInfo,
        paths: SwiftPaths,
    }

    #[derive(serde::Deserialize)]
    struct SwiftTargetInfo {
        #[serde(rename = "unversionedTriple")]
        unversioned_triple: String,
    }

    #[derive(serde::Deserialize)]
    struct SwiftPaths {
        #[serde(rename = "runtimeLibraryPaths")]
        runtime_library_paths: Vec<String>,
    }

    pub(super) fn update_identifier() {
        let content = std::fs::read_to_string("Cargo.toml").unwrap();
        let cargo: Cargo = toml::from_str(&content).unwrap();
        std::fs::write("identifier.txt", cargo.package.metadata.bundle.identifier).unwrap();
    }

    pub(super) fn link_swift() {
        let swift_target_info = get_swift_target_info();
        swift_target_info.paths.runtime_library_paths.iter().for_each(|path| {
            println!("cargo:rustc-link-search=native={}", path);
        });
    }

    pub(super) fn link_swift_package(package_name: &str, package_root: &str) {
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

    fn get_swift_target_info() -> SwiftTarget {
        let swift_target_info_str = std::process::Command::new("swift")
            .args(["-print-target-info"])
            .output()
            .unwrap()
            .stdout;
        serde_json::from_slice(&swift_target_info_str).unwrap()
    }
}

#[cfg(all(target_os = "macos", feature = "notifications"))]
use macos::*;

#[cfg(any(not(target_os = "macos"), not(feature = "notifications")))]
fn main() {}

#[cfg(all(target_os = "macos", feature = "notifications"))]
fn main() {
    update_identifier();
    link_swift();
    link_swift_package("macos_native", "./macos_native/");
}
