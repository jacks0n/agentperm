// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "AgentpermConfig",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "AgentpermConfig", targets: ["AgentpermConfig"]),
    ],
    targets: [
        .executableTarget(name: "AgentpermConfig"),
        .testTarget(name: "AgentpermConfigTests", dependencies: ["AgentpermConfig"]),
    ]
)
