import Foundation

public final class ConfigurationStore {
    public let url: URL
    public init(url: URL) { self.url = url }
    public func load() throws -> GuardConfiguration {
        guard FileManager.default.fileExists(atPath: url.path) else { return GuardConfiguration() }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= 1_048_576 else {
            throw GuardError.invalid("Файл настроек слишком большой.")
        }
        let config = try JSONDecoder().decode(GuardConfiguration.self, from: Data(contentsOf: url))
        try config.validate()
        return config
    }
    public func save(_ configuration: GuardConfiguration) throws {
        try configuration.validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(configuration)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

/// The distributed preparation app has no network-control backend or activation entry point.
public enum BuildSafety {
    public static let networkChangesPermitted = false
    public static let status = "Подготовка — сеть не меняется"
    public static func requestActivation() throws { throw GuardError.preparationOnly }
}
