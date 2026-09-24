// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "mop",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "MopUI", targets: ["MopUI"]),
        .library(name: "MopCore", targets: ["MopCore"]),
        .library(name: "MopAppSupport", targets: ["MopAppSupport"]),
        .library(name: "MopVault", targets: ["MopVault"]),
        .library(name: "MopCloudKit", targets: ["MopCloudKit"]),
        .library(name: "MopKeychain", targets: ["MopKeychain"]),
        .executable(name: "mop", targets: ["MopCLI"]),
        .executable(name: "MopApp", targets: ["MopApp"]),
        .executable(name: "mop-keychain-check", targets: ["MopKeychainCheck"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2"),
        .package(url: "https://github.com/DeVitoC/zxcvbn-swift.git", revision: "2d0c1137bab12e2c1dc13f167c650256bf60d0b8"),
    ],
    targets: [
        .target(name: "MopCore", dependencies: [.product(name: "zxcvbn", package: "zxcvbn-swift")]),
        .target(name: "MopAppSupport", dependencies: ["MopCore", "MopCloudKit", "MopVault", "MopAuth", "MopKeychain"]),
        .target(name: "MopUI", dependencies: ["MopAppSupport", "MopCore"]),
        .executableTarget(name: "MopApp", dependencies: ["MopUI"]),
        .testTarget(name: "MopAppSupportTests", dependencies: ["MopAppSupport", "MopCore"]),
        .testTarget(name: "MopAppTests", dependencies: ["MopUI", "MopAppSupport", "MopCore"]),
        .target(name: "MopAuth", dependencies: ["MopCore"]),
        .target(name: "MopKeychain", dependencies: ["MopCore", "MopAuth"]),
        .target(name: "MopCloudKit", dependencies: ["MopCore", "MopVault", "MopKeychain"]),
        .target(name: "MopVault", dependencies: ["MopCore", "MopAuth", "MopKeychain"]),
        .executableTarget(name: "MopCLI", dependencies: [
            "MopCore", "MopVault", "MopKeychain", "MopCloudKit", "MopAuth",
            .product(name: "ArgumentParser", package: "swift-argument-parser"),
        ]),
        .executableTarget(name: "MopKeychainCheck", dependencies: ["MopCore", "MopKeychain", "MopAuth"]),
        .testTarget(name: "MopCLITests", dependencies: ["MopCLI", "MopCore", "MopVault"]),
        .testTarget(name: "MopCoreTests", dependencies: ["MopCore"]),
        .testTarget(name: "MopKeychainTests", dependencies: ["MopKeychain", "MopCore"]),
        .testTarget(name: "MopCloudKitTests", dependencies: ["MopCloudKit", "MopVault", "MopCore"]),
        .testTarget(name: "MopVaultTests", dependencies: ["MopVault", "MopCore"]),
    ]
)
