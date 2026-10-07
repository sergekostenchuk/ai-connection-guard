import Foundation

/// Editable text is kept apart from the validated configuration, preserving IPv4/IPv6 selection.
public struct TunnelEditorDraft {
    public var proxyAddress: String
    public var proxyPort: String
    public var serverAddress: String
    public var serverPort: String
    public var process: ProgramTarget?
    public init(_ settings: TunnelSettings) {
        proxyAddress = settings.proxy.canonicalAddress ?? settings.proxy.address
        proxyPort = String(settings.proxy.port)
        serverAddress = settings.server?.address ?? ""
        serverPort = String(settings.server?.port ?? 443)
        process = settings.process
    }
    public func settings() throws -> TunnelSettings {
        guard let local = UInt16(proxyPort), let remote = UInt16(serverPort), remote > 0 else {
            throw GuardError.invalid("Порт должен быть числом от 1 до 65535.")
        }
        let value = TunnelSettings(proxy: Endpoint(address: proxyAddress, port: local), process: process,
                                   server: serverAddress.isEmpty ? nil : Endpoint(address: serverAddress, port: remote))
        try value.validateDraft()
        return value
    }
}
