import Foundation
import NetworkExtension
import ConnectionGuardCore

/// Kept separate from the menu-bar app. The preparation build refuses to start as a filter.
@objc(FilterProvider)
final class FilterProvider: NEFilterDataProvider {
    private var policy: GuardPolicy?
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        guard BuildSafety.networkChangesPermitted else {
            completionHandler(GuardError.preparationOnly)
            return
        }
        do {
            guard let data = filterConfiguration.vendorConfiguration?["policy"] as? Data, data.count <= 1_048_576 else {
                throw GuardError.invalid("Отсутствует политика фильтра.")
            }
            let configuration = try JSONDecoder().decode(GuardConfiguration.self, from: data)
            try configuration.validate()
            guard configuration.mode == .unrestricted || configuration.readinessProblems().isEmpty else {
                throw GuardError.invalid("Политика фильтра неполна.")
            }
            policy = GuardPolicy(configuration)
            // macOS excludes loopback from defaultAction. It must have explicit filter rules.
            let loopbackV4 = NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: "127.0.0.1", port: "0"),
                                           prefix: 8, protocol: .any)
            let loopbackV6 = NENetworkRule(destinationNetwork: NWHostEndpoint(hostname: "::1", port: "0"),
                                           prefix: 128, protocol: .any)
            let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: loopbackV4, action: .filterData),
                                                    NEFilterRule(networkRule: loopbackV6, action: .filterData)],
                                            defaultAction: .filterData)
            apply(settings) { error in completionHandler(error) }
        } catch { completionHandler(error) }
    }
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        policy = nil; completionHandler()
    }
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let policy else { return .drop() }
        guard let socket = flow as? NEFilterSocketFlow else {
            return policy.configuration.mode == .unrestricted ? .allow() : .drop()
        }
        let tokens = [flow.sourceAppAuditToken, flow.sourceProcessAuditToken].compactMap { $0 }
        var identities: [VerifiedProcess] = []
        var verified = !tokens.isEmpty
        for token in Set(tokens) {
            do { identities.append(try CodeIdentity.resolve(auditToken: token)) }
            catch { verified = false }
        }
        let transport: Transport = socket.socketProtocol == IPPROTO_TCP ? .tcp :
            (socket.socketProtocol == IPPROTO_UDP ? .udp : .other)
        guard flow.direction == .inbound || flow.direction == .outbound else { return .drop() }
        let candidate = ConnectionFlow(identities: identities, identityVerified: verified,
                                       remote: endpoint(socket.remoteEndpoint), local: endpoint(socket.localEndpoint),
                                       transport: transport, direction: flow.direction == .inbound ? .inbound : .outbound)
        return policy.decide(candidate).allowed ? .allow() : .drop()
    }
    private func endpoint(_ value: NWEndpoint?) -> Endpoint? {
        guard let host = value as? NWHostEndpoint, let port = UInt16(host.port) else { return nil }
        return Endpoint(address: host.hostname, port: port)
    }
}

@main
struct FilterMain {
    static func main() {
        // No side effects even when this executable is accidentally opened directly.
        guard BuildSafety.networkChangesPermitted else {
            fputs("AI Connection Guard: preparation build, filter activation disabled.\n", stderr)
            return
        }
        NEProvider.startSystemExtensionMode()
        dispatchMain()
    }
}
