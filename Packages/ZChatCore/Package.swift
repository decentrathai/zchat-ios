// swift-tools-version:6.0
// ZChatCore: the pure-Swift rules of ZChat for iOS (AGENTS.md rule 4). PAR-0001 (skeleton), PAR-0002 (ZMSG envelope).
import PackageDescription

let package = Package(
    name: "ZChatCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "ZChatCore", targets: ["ZChatProtocol"]),
    ],
    dependencies: [
        // SHA-256 on Linux only (plan IOS_PLAN_FINAL.md:219, annex A2): Apple builds use CryptoKit.
        // Tag 5.2.0 is a lightweight tag on commit b0b1963823fe828065ef49c09c8c9489f43cf7be.
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.2.0"),
    ],
    targets: [
        .target(
            name: "ZChatProtocol",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ]
        ),
        .testTarget(
            name: "ZChatProtocolTests",
            dependencies: ["ZChatProtocol"]
        ),
    ]
)
