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
        .package(url: "https://github.com/DeVitoC/zxcvbn-swift.git", revision: "2d0c1137bab12e2c1dc13f167c650256bf60d0b8"),
    ],
    targets: [
        .target(name: "MopCore", dependencies: [.product(name: "zxcvbn", package: "zxcvbn-swift")]),
        .target(name: "MopAppSupport", dependencies: ["MopCore", "MopCloudKit", "MopVault", "MopAuth", "MopKeychain"]),
        .executableTarget(name: "MopApp", dependencies: ["MopAppSupport", "MopCore"]),
        .testTarget(name: "MopAppSupportTests", dependencies: ["MopAppSupport", "MopCore"]),
        .testTarget(name: "MopAppTests", dependencies: ["MopApp", "MopAppSupport", "MopCore"]),
        .target(name: "MopAuth", dependencies: ["MopCore"]),
        .target(name: "MopKeychain", dependencies: ["MopCore", "MopAuth"]),
        .target(name: "MopCloudKit", dependencies: ["MopCore", "MopVault", "MopKeychain"]),
        .target(name: "MopVault", dependencies: ["MopCore", "MopAuth", "MopKeychain"]),
        .executableTarget(name: "MopCLI", dependencies: [
            "MopCore", "MopVault", "MopKeychain", "MopCloudKit", "MopAuth",
            .product(name: "ArgumentParser", package: "swift-argument-parser"),
        ]),
        .executableTarget(name: "MopKeychainCheck", dependencies: ["MopCore", "MopKeychain", "MopAuth"]),
        .executableTarget(name: "MopEnclaveCheck", dependencies: ["MopCore", "MopAuth", "MopVault", "MopKeychain"]),
        .testTarget(name: "MopCLITests", dependencies: ["MopCLI", "MopCore", "MopVault"]),
        .testTarget(name: "MopCoreTests", dependencies: ["MopCore"]),
        .testTarget(name: "MopKeychainTests", dependencies: ["MopKeychain", "MopCore"]),
        .testTarget(name: "MopCloudKitTests", dependencies: ["MopCloudKit", "MopVault", "MopCore"]),
        .testTarget(name: "MopVaultTests", dependencies: ["MopVault", "MopCore"]),
    ]
)
