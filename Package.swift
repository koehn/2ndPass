// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "mop",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "MopUI", targets: ["MopUI"]),
        .library(name: "MopCore", targets: ["MopCore"]),
        .library(name: "MopAppSupport", targets: ["MopAppSupport"]),
        .library(name: "MopVaultNext", targets: ["MopVaultNext"]),
        .library(name: "MopKeychain", targets: ["MopKeychain"]),
        .executable(name: "mop", targets: ["MopCLI"]),
        .executable(name: "MopApp", targets: ["MopApp"]),
        .executable(name: "mop-keychain-check", targets: ["MopKeychainCheck"]),
    ],
    dependencies: [
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", exact: "0.9.20"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2"),
        .package(url: "https://github.com/DeVitoC/zxcvbn-swift.git", revision: "2d0c1137bab12e2c1dc13f167c650256bf60d0b8"),
    ],
    targets: [
        .target(name: "MopCore", dependencies: [.product(name: "zxcvbn", package: "zxcvbn-swift")]),
        .target(name: "MopAppSupport", dependencies: ["ZIPFoundation", "MopCore", "MopAuth", "MopKeychain", "MopVaultNext"]),
        .target(name: "MopUI", dependencies: ["MopAppSupport", "MopCore", "MopVaultNext"]),
        .executableTarget(name: "MopApp", dependencies: ["MopUI"]),
        .testTarget(name: "MopAppSupportTests", dependencies: ["MopAppSupport", "MopCore", "MopVaultNext"]),
        .testTarget(name: "MopAppTests", dependencies: ["MopUI", "MopAppSupport", "MopCore"]),
        .target(name: "MopAuth", dependencies: ["MopCore"]),
        .target(name: "MopKeychain", dependencies: ["MopCore", "MopAuth"], exclude: ["KeychainStore.swift", "SynchronizedIdentityStore.swift"]),
        .target(name: "MopVaultNext", dependencies: ["MopCore", "MopKeychain"]),
        .testTarget(name: "MopVaultNextTests", dependencies: ["MopVaultNext", "MopCore"]),
        .executableTarget(name: "MopVaultNextCheck", dependencies: ["MopVaultNext", "MopCore", "MopAuth", "MopAppSupport"],
                          path: "prototypes/vault-next", exclude: ["enclave.swift", "cloud.swift"], sources: ["package-check.swift"]),
        .executableTarget(name: "MopCLI", dependencies: [
            "MopCore", "MopKeychain", "MopAuth", "MopAppSupport", "MopVaultNext",
            .product(name: "ArgumentParser", package: "swift-argument-parser"),
        ]),
        .executableTarget(name: "MopKeychainCheck", dependencies: ["MopCore", "MopKeychain", "MopAuth", "MopVaultNext"]),
        .testTarget(name: "MopCLITests", dependencies: ["MopCLI", "MopCore"]),
        .testTarget(name: "MopCoreTests", dependencies: ["MopCore"]),
    ]
)
