// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "CypheraKeychain",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(name: "CypheraKeychain", targets: ["CypheraKeychain"])
    ],
    targets: [
        .target(
            name: "CypheraKeychain",
            path: "Sources/CypheraKeychain"
        ),
        .testTarget(
            name: "CypheraKeychainTests",
            dependencies: ["CypheraKeychain"],
            path: "Tests/CypheraKeychainTests"
        )
    ]
)
