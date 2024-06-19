// swift-tools-version: 5.10
import PackageDescription

let package = Package(
  name: "macos_native",
  platforms: [
    .macOS(.v10_15)
  ],
  products: [
    .library(
      name: "macos_native",
      type: .static,
      targets: ["macos_native"])
  ],
  targets: [
    .target(
      name: "macos_native")
  ]
)
