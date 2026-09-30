// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "2ndpass",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "MopLocalIdentity", targets: ["MopLocalIdentity"]),
        .library(name: "MopUI", targets: ["MopUI"]),
        .library(name: "MopCore", targets: ["MopCore"]),
        .library(name: "MopAppSupport", targets: ["MopAppSupport"]),
        .library(name: "MopVaultNext", targets: ["MopVaultNext"]),
        .library(name: "MopKeychain", targets: ["MopKeychain"]),
        .executable(name: "sp", targets: ["MopCLI"]),
        .executable(name: "MopApp", targets: ["MopApp"]),
        .executable(name: "sp-keychain-check", targets: ["MopKeychainCheck"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.21.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.3"),
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", exact: "0.9.20"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2"),
        .package(url: "https://github.com/DeVitoC/zxcvbn-swift.git", revision: "2d0c1137bab12e2c1dc13f167c650256bf60d0b8"),
    ],
    targets: [
        .target(name: "MopCore", dependencies: [.product(name: "zxcvbn", package: "zxcvbn-swift")]),
        .target(name: "MopLocalIdentity", dependencies: ["MopCore", "MopAuth", "MopKeychain", .product(name: "X509", package: "swift-certificates"), .product(name: "SwiftASN1", package: "swift-asn1")]),
        .testTarget(name: "MopLocalIdentityTests", dependencies: ["MopLocalIdentity", "MopCore"]),
        .target(name: "MopAppSupport", dependencies: ["MopLocalIdentity", "ZIPFoundation", "MopCore", "MopAuth", "MopKeychain", "MopVaultNext"]),
        .target(name: "MopUI", dependencies: ["MopLocalIdentity", "MopAppSupport", "MopCore", "MopVaultNext"], resources: [.process("Resources")]),
        .executableTarget(name: "MopApp", dependencies: ["MopUI"]),
        .testTarget(name: "MopAppSupportTests", dependencies: ["MopLocalIdentity", "MopAppSupport", "MopCore", "MopVaultNext"]),
        .testTarget(name: "MopAppTests", dependencies: ["MopLocalIdentity", "MopUI", "MopAppSupport", "MopCore"]),
        .target(name: "MopAuth", dependencies: ["MopCore"]),
        .target(name: "MopKeychain", dependencies: ["MopCore", "MopAuth"], exclude: ["KeychainStore.swift", "SynchronizedIdentityStore.swift"]),
        .target(name: "MopVaultNext", dependencies: ["MopCore", "MopKeychain"]),
        .testTarget(name: "MopVaultNextTests", dependencies: ["MopVaultNext", "MopCore"]),
        .executableTarget(name: "MopVaultNextCheck", dependencies: ["MopVaultNext", "MopCore", "MopAuth", "MopAppSupport"],
                          path: "prototypes/vault-next", exclude: ["enclave.swift", "cloud.swift"], sources: ["package-check.swift"]),
        .executableTarget(name: "MopCLI", dependencies: ["MopLocalIdentity",
            "MopCore", "MopKeychain", "MopAuth", "MopAppSupport", "MopVaultNext",
            .product(name: "ArgumentParser", package: "swift-argument-parser"),
        ]),
        .executableTarget(name: "MopKeychainCheck", dependencies: ["MopCore", "MopKeychain", "MopAuth", "MopVaultNext"]),
        .testTarget(name: "MopCLITests", dependencies: ["MopLocalIdentity", "MopCLI", "MopCore"]),
        .testTarget(name: "MopCoreTests", dependencies: ["MopCore"]),
    ]
)
