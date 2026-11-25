// swift-tools-version: 6.4
import PackageDescription

let strict: [SwiftSetting] = [
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .treatAllWarnings(as: .error),
]

let package = Package(
    name: "signd",
    platforms: [.macOS(.v27)],
    products: [
        .executable(name: "signd", targets: ["signd"]),
        .library(name: "SigndCLI", targets: ["SigndCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.105.2"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.1.1"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.5"),
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.21.2"),
        .package(url: "https://github.com/tuist/Noora.git", exact: "0.57.7"),
        .package(url: "https://github.com/onevcat/Rainbow.git", exact: "4.2.2"),
        .package(url: "https://github.com/victor-software-house/swift-onepassword.git", exact: "0.0.4"),
        .package(url: "https://github.com/victor-software-house/swift-daemon-services.git", exact: "0.0.2"),
    ],
    targets: [
        // The SSH encoding of keys and signatures, with no platform code.
        .target(name: "SSHEncoding", swiftSettings: strict),
        // The SSH agent messages (RFC 9987), with no platform code.
        .target(name: "AgentProtocol", dependencies: ["SSHEncoding"], swiftSettings: strict),
        // Keys: the keychain store, the Secure Enclave, and signing in memory.
        .target(
            name: "KeyStore",
            dependencies: [
                "SSHEncoding", "AgentProtocol",
                .product(name: "CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            swiftSettings: strict
        ),
        // Sharing keys between devices through iCloud, and the SSH routing files for their hosts.
        .target(name: "Sync", dependencies: ["KeyStore", "SSHEncoding"], swiftSettings: strict),
        // The 1Password backup: the check that the service account lists the vault.
        .target(
            name: "Backup",
            dependencies: [
                "KeyStore", "SSHEncoding", "Sync",
                .product(name: "OnePassword", package: "swift-onepassword"),
            ],
            swiftSettings: strict
        ),
        // The updater: the check, the verified download, the swap of the app and the restart of the agents.
        .target(name: "Updates", swiftSettings: strict),
        // The agent's state and the socket server.
        .target(
            name: "AgentServer",
            dependencies: [
                "AgentProtocol", "Backup", "KeyStore", "SSHEncoding", "Sync",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ],
            swiftSettings: strict
        ),
        // The command line and the agent: every command, with no entry point.
        // The Xcode app target links this library, and the executable below calls it.
        .target(
            name: "SigndCLI",
            dependencies: [
                "AgentServer", "AgentProtocol", "Backup", "KeyStore", "SSHEncoding", "Sync", "Updates",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "KeychainIdentity", package: "swift-daemon-services"),
                .product(name: "Noora", package: "Noora"),
                .product(name: "Rainbow", package: "Rainbow"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            swiftSettings: strict
        ),
        .executableTarget(
            name: "signd",
            dependencies: ["SigndCLI", .product(name: "ArgumentParser", package: "swift-argument-parser")],
            swiftSettings: strict
        ),
        .testTarget(
            name: "SigndTests",
            dependencies: [
                "SSHEncoding", "AgentProtocol", "Backup", "KeyStore", "AgentServer", "Sync", "Updates", "SigndCLI",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
                .product(name: "KeychainIdentity", package: "swift-daemon-services"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            resources: [.copy("Fixtures")],
            swiftSettings: strict
        ),
    ]
)
