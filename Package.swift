// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "mop",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "mop", targets: ["MopCLI"]),
        .executable(name: "MopApp", targets: ["MopApp"]),
        .executable(name: "mop-keychain-check", targets: ["MopKeychainCheck"]),
        .executable(name: "mop-enclave-check", targets: ["MopEnclaveCheck"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2"),
    ],
    targets: [
        .target(name: "MopCore"),
        .target(name: "MopAppSupport", dependencies: ["MopCore"]),
        .executableTarget(name: "MopApp", dependencies: ["MopAppSupport", "MopCore"]),
        .testTarget(name: "MopAppSupportTests", dependencies: ["MopAppSupport", "MopCore"]),
        .testTarget(name: "MopAppTests", dependencies: ["MopApp", "MopAppSupport", "MopCore"]),
        .target(name: "MopAuth", dependencies: ["MopCore"]),
        .target(name: "MopKeychain", dependencies: ["MopCore", "MopAuth"]),
        .target(name: "MopCloudKit", dependencies: ["MopCore", "MopVault", "MopKeychain"]),
        .target(name: "MopVault", dependencies: ["MopCore", "MopAuth", "MopKeychain"]),
        .executableTarget(name: "MopCLI", dependencies: [
            "MopCore", "MopVault", "MopKeychain", "MopCloudKit",
            .product(name: "ArgumentParser", package: "swift-argument-parser"),
        ]),
        .executableTarget(name: "MopKeychainCheck", dependencies: ["MopCore", "MopKeychain", "MopAuth"]),
        .executableTarget(name: "MopEnclaveCheck", dependencies: ["MopCore", "MopAuth", "MopVault", "MopKeychain"]),
        .testTarget(name: "MopCLITests", dependencies: ["MopCLI", "MopCore"]),
        .testTarget(name: "MopCoreTests", dependencies: ["MopCore"]),
        .testTarget(name: "MopKeychainTests", dependencies: ["MopKeychain", "MopCore"]),
        .testTarget(name: "MopCloudKitTests", dependencies: ["MopCloudKit", "MopVault", "MopCore"]),
        .testTarget(name: "MopVaultTests", dependencies: ["MopVault", "MopCore"]),
    ]
)
