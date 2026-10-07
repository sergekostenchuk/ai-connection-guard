import Foundation
import Darwin

public enum GuardError: Error, LocalizedError, Equatable {
    case invalid(String)
    case preparationOnly
    public var errorDescription: String? {
        switch self {
        case .invalid(let message): return message
        case .preparationOnly: return "Это сборка для подготовки. Сетевые ограничения не применяются."
        }
    }
}

public enum DesiredMode: String, Codable, CaseIterable {
    case protected, unrestricted
    public var title: String { self == .protected ? "Защищать выбранные сервисы" : "Без ограничений · поездка" }
}

public enum TargetKind: String, Codable { case application, executable, browser }

/// Obtained from a selected, code-signed executable, never from a display name.
public struct ProgramTarget: Codable, Equatable, Identifiable {
    public var id: UUID
    public var kind: TargetKind
    public var path: String
    public var signingIdentifier: String
    public var teamIdentifier: String?
    public var codeHash: String

    public init(id: UUID = UUID(), kind: TargetKind, path: String, signingIdentifier: String,
                teamIdentifier: String?, codeHash: String) {
        self.id = id; self.kind = kind; self.path = path; self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier; self.codeHash = codeHash
    }

    public func validate() throws {
        guard path.hasPrefix("/"), !path.contains("/../"), !path.contains("/./"), !path.hasSuffix("/"),
              path != "/", !signingIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              [40, 64].contains(codeHash.count), codeHash.allSatisfy({ $0.isHexDigit && $0.isASCII }),
              teamIdentifier == nil || !(teamIdentifier?.isEmpty ?? true) else {
            throw GuardError.invalid("Неполная или некорректная идентификация программы.")
        }
        if kind != .executable && !path.hasSuffix(".app") {
            throw GuardError.invalid("Выберите пакет приложения .app.")
        }
    }
}

public struct Service: Codable, Equatable, Identifiable {
    public var id: UUID
    public var name: String
    public var website: String
    public var enabled: Bool
    public var programs: [ProgramTarget]
    public var browser: ProgramTarget?

    public init(id: UUID = UUID(), name: String, website: String, enabled: Bool = true,
                programs: [ProgramTarget] = [], browser: ProgramTarget? = nil) {
        self.id = id; self.name = name; self.website = website; self.enabled = enabled
        self.programs = programs; self.browser = browser
    }
    public var allTargets: [ProgramTarget] { programs + (browser.map { [$0] } ?? []) }
    public static var presets: [Service] {
        [Service(name: "Claude", website: "https://claude.ai/"),
         Service(name: "Codex", website: "https://chatgpt.com/codex"),
         Service(name: "Grok", website: "https://grok.com/"),
         Service(name: "Gemini", website: "https://gemini.google.com/")]
    }
    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, name.count <= 80 else {
            throw GuardError.invalid("Введите название сервиса (до 80 символов).")
        }
        guard let url = URLComponents(string: website), url.scheme == "https",
              let host = url.host, !host.isEmpty, !host.contains(" "),
              url.user == nil, url.password == nil else {
            throw GuardError.invalid("Адрес сервиса должен начинаться с https:// и не содержать логин или пароль.")
        }
        for program in programs {
            try program.validate()
            guard program.kind != .browser else { throw GuardError.invalid("Браузер задаётся отдельно от приложений.") }
        }
        if let browser {
            try browser.validate()
            guard browser.kind == .browser else { throw GuardError.invalid("Неверный тип браузера.") }
        }
        guard Set(allTargets.map(\.id)).count == allTargets.count else {
            throw GuardError.invalid("Повторяющаяся идентификация программы.")
        }
    }
}

public struct Endpoint: Codable, Equatable, Hashable {
    public var address: String
    public var port: UInt16
    public init(address: String, port: UInt16) { self.address = address; self.port = port }
    public var canonicalAddress: String? {
        guard !address.isEmpty, address.allSatisfy({ $0.isASCII && ($0.isHexDigit || $0 == ":" || $0 == ".") }) else { return nil }
        var v4 = in_addr(); var v6 = in6_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &v4, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return String(cString: buffer)
        }
        if inet_pton(AF_INET6, address, &v6) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            let value = String(cString: buffer)
            if value.hasPrefix("::ffff:") { return String(value.dropFirst(7)) }
            return value
        }
        return nil
    }
    public var isLoopback: Bool {
        canonicalAddress == "127.0.0.1" || canonicalAddress == "::1"
    }
    public func sameSocket(as other: Endpoint) -> Bool {
        guard let a = canonicalAddress, let b = other.canonicalAddress else { return false }
        return a == b && port == other.port
    }
}

public struct TunnelSettings: Codable, Equatable {
    public var proxy: Endpoint
    public var process: ProgramTarget?
    public var server: Endpoint?
    public init(proxy: Endpoint = Endpoint(address: "127.0.0.1", port: 28761),
                process: ProgramTarget? = nil, server: Endpoint? = nil) {
        self.proxy = proxy; self.process = process; self.server = server
    }
    public func validateDraft() throws {
        guard proxy.isLoopback, proxy.port >= 1024 else {
            throw GuardError.invalid("Локальный прокси: только 127.0.0.1 или ::1, порт 1024–65535.")
        }
        if let process { try process.validate() }
        if let server {
            guard server.port > 0, let ip = server.canonicalAddress,
                  !ip.hasPrefix("127."), ip != "::1", ip != "0.0.0.0", ip != "::" else {
                throw GuardError.invalid("Для сервера нужен отдельный IP-адрес и порт.")
            }
        }
    }
}

public struct GuardConfiguration: Codable, Equatable {
    public static let schemaVersion = 1
    public var schemaVersion: Int
    public var mode: DesiredMode
    public var services: [Service]
    public var tunnel: TunnelSettings
    public init(mode: DesiredMode = .protected, services: [Service] = Service.presets,
                tunnel: TunnelSettings = TunnelSettings()) {
        self.schemaVersion = Self.schemaVersion; self.mode = mode; self.services = services; self.tunnel = tunnel
    }
    public var protectedTargets: [ProgramTarget] { services.filter(\.enabled).flatMap(\.allTargets) }
    public func validate() throws {
        guard schemaVersion == Self.schemaVersion else { throw GuardError.invalid("Неизвестная версия настроек.") }
        guard Set(services.map(\.id)).count == services.count else { throw GuardError.invalid("Повторяющийся сервис.") }
        let names = services.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        guard Set(names).count == names.count else { throw GuardError.invalid("Сервис с таким названием уже существует.") }
        for service in services { try service.validate() }
        try tunnel.validateDraft()
        if let process = tunnel.process {
            guard !protectedTargets.contains(where: { $0.path == process.path || $0.signingIdentifier == process.signingIdentifier }) else {
                throw GuardError.invalid("Туннель и защищаемый сервис должны быть разными программами.")
            }
        }
    }
    public func readinessProblems() -> [String] {
        var problems: [String] = []
        if protectedTargets.isEmpty { problems.append("Не выбраны приложения или браузеры.") }
        if tunnel.process == nil { problems.append("Не выбран локальный Xray.") }
        if tunnel.server == nil { problems.append("Не указан доверенный сервер туннеля.") }
        for service in services where service.enabled && service.allTargets.isEmpty {
            problems.append("\(service.name): выберите приложение или браузер.")
        }
        return problems
    }
    @discardableResult public mutating func updateDraftService(_ service: Service) -> Bool {
        guard let index = services.firstIndex(where: { $0.id == service.id }) else { return false }
        services[index] = service
        return true
    }
    public func browserSharing(_ target: ProgramTarget) -> [String] {
        services.filter { $0.enabled && $0.browser?.path == target.path }.map(\.name)
    }
}
