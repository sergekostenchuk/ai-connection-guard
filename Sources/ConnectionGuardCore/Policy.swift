import Foundation

/// Only the provider's audit-token / code-signature resolver creates these in production.
public struct VerifiedProcess: Equatable {
    public var executablePath: String
    public var signingIdentifier: String
    public var teamIdentifier: String?
    public var codeHash: String
    public init(executablePath: String, signingIdentifier: String, teamIdentifier: String?, codeHash: String) {
        self.executablePath = executablePath; self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier; self.codeHash = codeHash
    }
    public func matches(_ target: ProgramTarget) -> Bool {
        if let team = target.teamIdentifier {
            guard team == teamIdentifier else { return false }
            // Team + signing identifier survives upgrades and moving the main executable.
            if signingIdentifier == target.signingIdentifier { return true }
            // Signed helpers inside the exact application bundle are also protected.
            return target.kind != .executable && executablePath.hasPrefix(target.path + "/Contents/")
        }
        // Ad-hoc signed CLI updates require re-enrolment; never trust just their name.
        return codeHash.lowercased() == target.codeHash.lowercased() && signingIdentifier == target.signingIdentifier
    }
    public func occupies(_ target: ProgramTarget) -> Bool {
        executablePath == target.path ||
        (target.kind != .executable && executablePath.hasPrefix(target.path + "/Contents/")) ||
        signingIdentifier == target.signingIdentifier
    }
}

public enum Transport { case tcp, udp, other }
public enum FlowDirection { case outbound, inbound }
public struct ConnectionFlow {
    /// Both the socket process and responsible app, when provided by macOS.
    public var identities: [VerifiedProcess]
    public var identityVerified: Bool
    public var remote: Endpoint?
    public var local: Endpoint?
    public var transport: Transport
    public var direction: FlowDirection
    public init(identities: [VerifiedProcess], identityVerified: Bool = true, remote: Endpoint?,
                local: Endpoint? = nil, transport: Transport = .tcp, direction: FlowDirection = .outbound) {
        self.identities = identities; self.identityVerified = identityVerified; self.remote = remote
        self.local = local; self.transport = transport; self.direction = direction
    }
}

public enum Decision: String, Equatable {
    case allowUnrestricted, allowUnrelated, allowProxy, allowTunnel, allowProxyListener
    case denyInvalidPolicy, denyUnknownIdentity, denyIdentityChanged, denyDirect, denyProtocol, denyUnknownEndpoint, denyWrongListener
    public var allowed: Bool { rawValue.hasPrefix("allow") }
    public var explanation: String {
        switch self {
        case .allowUnrestricted: return "Разрешено: режим без ограничений."
        case .allowUnrelated: return "Разрешено: программа не входит в список защиты."
        case .allowProxy: return "Разрешено: соединение с локальным прокси."
        case .allowTunnel: return "Разрешено: туннель соединяется с заданным сервером."
        case .allowProxyListener: return "Разрешено: подключение принимает выбранный процесс туннеля."
        case .denyInvalidPolicy: return "Запрещено: политика неполна или повреждена."
        case .denyUnknownIdentity: return "Запрещено: macOS не подтвердила процесс."
        case .denyIdentityChanged: return "Запрещено: подпись выбранной программы изменилась."
        case .denyDirect: return "Запрещено: соединение обходит заданный туннель."
        case .denyProtocol: return "Запрещено: для защищаемой программы разрешён только TCP."
        case .denyUnknownEndpoint: return "Запрещено: IP-адрес или порт не определён."
        case .denyWrongListener: return "Запрещено: порт прокси принадлежит другой программе."
        }
    }
}

/// An immutable policy per provider lifetime. Draft edits cannot loosen running rules.
public struct GuardPolicy {
    public let configuration: GuardConfiguration
    private let valid: Bool
    public init(_ configuration: GuardConfiguration) {
        self.configuration = configuration
        valid = (try? configuration.validate()) != nil &&
            (configuration.mode == .unrestricted || configuration.readinessProblems().isEmpty)
    }
    public func decide(_ flow: ConnectionFlow) -> Decision {
        guard valid else { return .denyInvalidPolicy }
        if configuration.mode == .unrestricted { return .allowUnrestricted }
        guard flow.identityVerified, !flow.identities.isEmpty else { return .denyUnknownIdentity }
        let targets = configuration.protectedTargets
        let tunnel = configuration.tunnel.process!
        let enrolled = targets + [tunnel]
        for identity in flow.identities {
            if enrolled.contains(where: { identity.occupies($0) && !identity.matches($0) }) {
                return .denyIdentityChanged
            }
        }
        let isTunnel = flow.identities.contains { $0.matches(tunnel) }
        let isProtected = flow.identities.contains { identity in targets.contains { identity.matches($0) } }
        // Any program binding the proxy port is rejected unless it is the enrolled tunnel.
        if flow.direction == .inbound, flow.local?.sameSocket(as: configuration.tunnel.proxy) == true {
            guard isTunnel else { return .denyWrongListener }
            guard flow.transport == .tcp, flow.remote?.isLoopback == true else { return .denyDirect }
            return .allowProxyListener
        }
        guard isProtected || isTunnel else { return .allowUnrelated }
        guard flow.transport == .tcp else { return .denyProtocol }
        guard let remote = flow.remote, remote.canonicalAddress != nil, remote.port > 0 else { return .denyUnknownEndpoint }
        guard flow.direction == .outbound else { return .denyDirect }
        // When a process is attributed both to a protected app and the tunnel, prefer the restrictive role.
        if isProtected {
            return remote.sameSocket(as: configuration.tunnel.proxy) ? .allowProxy : .denyDirect
        }
        return remote.sameSocket(as: configuration.tunnel.server!) ? .allowTunnel : .denyDirect
    }
}
