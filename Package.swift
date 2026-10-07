// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AIConnectionGuard", platforms: [.macOS(.v13)],
    products: [.executable(name: "ConnectionGuard", targets: ["ConnectionGuard"]),
               .executable(name: "ConnectionGuardFilter", targets: ["ConnectionGuardFilter"])],
    targets: [
        .target(name: "ConnectionGuardCore"),
        .executableTarget(name: "ConnectionGuard", dependencies: ["ConnectionGuardCore"]),
        .executableTarget(name: "ConnectionGuardFilter", dependencies: ["ConnectionGuardCore"]),
        .testTarget(name: "ConnectionGuardCoreTests", dependencies: ["ConnectionGuardCore"])
    ]
)
