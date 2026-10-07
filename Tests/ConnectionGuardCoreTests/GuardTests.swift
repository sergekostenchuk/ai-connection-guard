import XCTest
@testable import ConnectionGuardCore

final class GuardTests: XCTestCase {
    let app = ProgramTarget(kind: .application, path: "/Applications/AI.app", signingIdentifier: "test.ai",
                            teamIdentifier: "AITEAM", codeHash: String(repeating: "a", count: 40))
    let browser = ProgramTarget(kind: .browser, path: "/Applications/Google Chrome.app", signingIdentifier: "com.google.Chrome",
                                teamIdentifier: "BROWSERTEAM", codeHash: String(repeating: "b", count: 40))
    let tunnel = ProgramTarget(kind: .executable, path: "/opt/guard/xray", signingIdentifier: "xray",
                               teamIdentifier: nil, codeHash: String(repeating: "c", count: 40))
    let external = Endpoint(address: "203.0.113.10", port: 443)
    let proxy = Endpoint(address: "127.0.0.1", port: 28761)
    func identity(_ target: ProgramTarget, path: String? = nil) -> VerifiedProcess {
        VerifiedProcess(executablePath: path ?? target.path, signingIdentifier: target.signingIdentifier,
                        teamIdentifier: target.teamIdentifier, codeHash: target.codeHash)
    }
    func configuration() -> GuardConfiguration {
        GuardConfiguration(services: [Service(name: "AI", website: "https://example.com", programs: [app], browser: browser)],
                           tunnel: TunnelSettings(proxy: proxy, process: tunnel, server: external))
    }
    func flow(_ remote: Endpoint?, target: ProgramTarget? = nil, transport: Transport = .tcp) -> ConnectionFlow {
        ConnectionFlow(identities: [identity(target ?? app)], remote: remote, transport: transport)
    }

    func testDefaultsArePreparationNotActiveProtection() throws {
        XCTAssertFalse(BuildSafety.networkChangesPermitted)
        XCTAssertThrowsError(try BuildSafety.requestActivation()) { XCTAssertEqual($0 as? GuardError, .preparationOnly) }
        XCTAssertEqual(GuardConfiguration().services.map(\.name), ["Claude", "Codex", "Grok", "Gemini"])
        XCTAssertFalse(GuardConfiguration().readinessProblems().isEmpty)
        XCTAssertEqual(GuardPolicy(GuardConfiguration()).decide(flow(proxy)), .denyInvalidPolicy)
    }
    func testProtectedAppOnlyUsesExactProxySocket() {
        let policy = GuardPolicy(configuration())
        XCTAssertEqual(policy.decide(flow(proxy)), .allowProxy)
        for endpoint in [external, Endpoint(address: "127.0.0.1", port: 80),
                         Endpoint(address: "127.0.0.2", port: proxy.port), Endpoint(address: "::1", port: proxy.port),
                         Endpoint(address: "2001:db8::1", port: 443)] {
            XCTAssertEqual(policy.decide(flow(endpoint)), .denyDirect)
        }
    }
    func testBrowserAlsoBlocksDirectTraffic() {
        let policy = GuardPolicy(configuration())
        XCTAssertEqual(policy.decide(flow(proxy, target: browser)), .allowProxy)
        XCTAssertEqual(policy.decide(flow(external, target: browser)), .denyDirect)
    }
    func testUDPAndOtherProtocolsHaveNoFallback() {
        let policy = GuardPolicy(configuration())
        for target in [app, browser, tunnel] {
            XCTAssertEqual(policy.decide(flow(proxy, target: target, transport: .udp)), .denyProtocol)
            XCTAssertEqual(policy.decide(flow(proxy, target: target, transport: .other)), .denyProtocol)
        }
    }
    func testUnresolvedEndpointsDoNotSilentlyPass() {
        let policy = GuardPolicy(configuration())
        for endpoint in [nil, Endpoint(address: "localhost", port: proxy.port), Endpoint(address: "203.0.113.10", port: 0)] {
            XCTAssertEqual(policy.decide(flow(endpoint)), .denyUnknownEndpoint)
        }
    }
    func testTunnelOnlyUsesPinnedEndpoint() {
        let policy = GuardPolicy(configuration())
        XCTAssertEqual(policy.decide(flow(external, target: tunnel)), .allowTunnel)
        for endpoint in [proxy, Endpoint(address: "203.0.113.11", port: 443), Endpoint(address: external.address, port: 8443)] {
            XCTAssertEqual(policy.decide(flow(endpoint, target: tunnel)), .denyDirect)
        }
    }
    func testTravelModeReleasesRestrictionsIncludingUnknownProcesses() {
        var config = configuration(); config.mode = .unrestricted
        let policy = GuardPolicy(config)
        XCTAssertEqual(policy.decide(flow(external)), .allowUnrestricted)
        XCTAssertEqual(policy.decide(ConnectionFlow(identities: [], identityVerified: false, remote: nil, transport: .udp)), .allowUnrestricted)
        config.mode = .protected
        XCTAssertEqual(GuardPolicy(config).decide(flow(external)), .denyDirect)
    }
    func testUnrelatedSignedAppKeepsNetwork() {
        let other = VerifiedProcess(executablePath: "/Applications/Other.app/Contents/MacOS/main", signingIdentifier: "other",
                                    teamIdentifier: "OTHER", codeHash: String(repeating: "d", count: 40))
        XCTAssertEqual(GuardPolicy(configuration()).decide(ConnectionFlow(identities: [other], remote: external)), .allowUnrelated)
    }
    func testUnknownOrPartiallyFailedIdentityIsDenied() {
        let policy = GuardPolicy(configuration())
        XCTAssertEqual(policy.decide(ConnectionFlow(identities: [], remote: external)), .denyUnknownIdentity)
        XCTAssertEqual(policy.decide(ConnectionFlow(identities: [identity(app)], identityVerified: false, remote: proxy)), .denyUnknownIdentity)
    }
    func testResponsibleAppProtectsSystemNetworkingHelper() {
        let system = VerifiedProcess(executablePath: "/usr/libexec/system", signingIdentifier: "com.apple.system",
                                     teamIdentifier: "APPLE", codeHash: String(repeating: "0", count: 40))
        XCTAssertEqual(GuardPolicy(configuration()).decide(ConnectionFlow(identities: [system, identity(app)], remote: external)), .denyDirect)
    }
    func testSignedAppHelpersAndMovedMainAreMatched() {
        var helper = identity(app, path: app.path + "/Contents/Frameworks/Helper.app/Contents/MacOS/Helper")
        helper.signingIdentifier = "test.ai.helper"
        XCTAssertTrue(helper.matches(app))
        let moved = identity(app, path: "/tmp/AI.app/Contents/MacOS/main")
        XCTAssertTrue(moved.matches(app))
        XCTAssertEqual(GuardPolicy(configuration()).decide(ConnectionFlow(identities: [helper], remote: external)), .denyDirect)
    }
    func testSimilarBundlePathIsNotAHelper() {
        var fake = identity(app, path: app.path + ".evil/Contents/MacOS/helper")
        fake.signingIdentifier = "other.helper"
        XCTAssertFalse(fake.matches(app))
    }
    func testSameNameOrPathWithWrongSignerIsDenied() {
        var fake = identity(app, path: app.path + "/Contents/MacOS/AI")
        fake.teamIdentifier = "IMPOSTOR"
        XCTAssertEqual(GuardPolicy(configuration()).decide(ConnectionFlow(identities: [fake], remote: proxy)), .denyIdentityChanged)
    }
    func testAdHocCLIChangeRequiresReEnrollment() {
        var updated = identity(tunnel); updated.codeHash = String(repeating: "e", count: 40)
        XCTAssertEqual(GuardPolicy(configuration()).decide(ConnectionFlow(identities: [updated], remote: external)), .denyIdentityChanged)
    }
    func testProxyPortCannotBeReplacedByAnotherListener() {
        let policy = GuardPolicy(configuration())
        let peer = Endpoint(address: "127.0.0.1", port: 50000)
        XCTAssertEqual(policy.decide(ConnectionFlow(identities: [identity(tunnel)], remote: peer, local: proxy, direction: .inbound)), .allowProxyListener)
        XCTAssertEqual(policy.decide(ConnectionFlow(identities: [identity(app)], remote: peer, local: proxy, direction: .inbound)), .denyWrongListener)
        XCTAssertEqual(policy.decide(ConnectionFlow(identities: [identity(tunnel)], remote: external, local: proxy, direction: .inbound)), .denyDirect)
    }
    func testProtectedInboundSocketsDenied() {
        XCTAssertEqual(GuardPolicy(configuration()).decide(ConnectionFlow(identities: [identity(app)], remote: external,
                                                                         local: Endpoint(address: "127.0.0.1", port: 9999), direction: .inbound)), .denyDirect)
    }
    func testIPv6AndMappedIPv4AreNormalizedWithoutBroadeningAllowlist() {
        XCTAssertTrue(Endpoint(address: "::ffff:127.0.0.1", port: proxy.port).sameSocket(as: proxy))
        XCTAssertTrue(Endpoint(address: "0:0:0:0:0:0:0:1", port: 99).sameSocket(as: Endpoint(address: "::1", port: 99)))
        for address in ["127.1", "2130706433", "127.0.0.1.evil", "127.0.0.1%lo0", "::1%lo0", " 127.0.0.1", ""] {
            XCTAssertNil(Endpoint(address: address, port: 1).canonicalAddress, address)
        }
    }
    func testSharedBrowserRemainsProtectedUntilLastServiceDisabled() {
        var config = configuration()
        config.services.append(Service(name: "Second", website: "https://second.example.com", browser: browser))
        XCTAssertEqual(config.browserSharing(browser), ["AI", "Second"])
        config.services[0].enabled = false
        XCTAssertEqual(GuardPolicy(config).decide(flow(external, target: browser)), .denyDirect)
        config.services[1].enabled = false
        // No selected protection at all is an invalid protected policy, never an implicit unrestricted mode.
        XCTAssertEqual(GuardPolicy(config).decide(flow(external, target: browser)), .denyInvalidPolicy)
    }
    func testDisabledServiceIsExcludedWhenAnotherServiceIsStillProtected() {
        var config = configuration()
        config.services[0].browser = nil
        config.services.append(Service(name: "Browser only", website: "https://second.example.com", browser: browser))
        config.services[0].enabled = false
        XCTAssertEqual(GuardPolicy(config).decide(flow(external)), .allowUnrelated)
        XCTAssertEqual(GuardPolicy(config).decide(flow(external, target: browser)), .denyDirect)
    }
    func testPolicySnapshotCannotBeChangedByEditingDraft() {
        var config = configuration(); let policy = GuardPolicy(config)
        config.mode = .unrestricted; config.services.removeAll()
        XCTAssertEqual(policy.decide(flow(external)), .denyDirect)
    }
    func testMissingRequiredFieldsDoNotDefaultToUnrestricted() throws {
        let encoded = try JSONEncoder().encode(configuration())
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        for key in ["schemaVersion", "mode", "services", "tunnel"] {
            var missing = object; missing.removeValue(forKey: key)
            XCTAssertThrowsError(try JSONDecoder().decode(GuardConfiguration.self, from: JSONSerialization.data(withJSONObject: missing)), key)
        }
        var unknown = configuration(); unknown.schemaVersion = 999
        XCTAssertThrowsError(try unknown.validate())
        XCTAssertEqual(GuardPolicy(unknown).decide(flow(proxy)), .denyInvalidPolicy)
    }
    func testMissingServiceIdentityFieldsAreRejected() throws {
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(app)) as? [String: Any])
        for key in ["id", "kind", "path", "signingIdentifier", "codeHash"] {
            var missing = object; missing.removeValue(forKey: key)
            XCTAssertThrowsError(try JSONDecoder().decode(ProgramTarget.self, from: JSONSerialization.data(withJSONObject: missing)), key)
        }
        var broken = app; broken.codeHash = "fake"; XCTAssertThrowsError(try broken.validate())
        broken = app; broken.path = "/Applications/../AI.app"; XCTAssertThrowsError(try broken.validate())
    }
    func testConfigurationRejectsDuplicateServicesAndBadURLs() throws {
        var config = configuration(); config.services.append(config.services[0]); XCTAssertThrowsError(try config.validate())
        config = configuration(); config.services.append(Service(name: " ai ", website: "https://example.com")); XCTAssertThrowsError(try config.validate())
        for url in ["http://example.com", "javascript:alert(1)", "https://user:password@example.com", "--no-proxy-server", "https://"] {
            XCTAssertThrowsError(try Service(name: "Test", website: url).validate(), url)
        }
        XCTAssertThrowsError(try Service(name: "  ", website: "https://example.com").validate())
    }
    func testTunnelCannotShareProtectedIdentity() {
        var config = configuration(); config.tunnel.process = app
        XCTAssertThrowsError(try config.validate())
        XCTAssertEqual(GuardPolicy(config).decide(flow(external)), .denyInvalidPolicy)
    }
    func testMissingTunnelAndWrongProxyAreInvalidPolicies() {
        var config = configuration(); config.tunnel.process = nil
        XCTAssertEqual(GuardPolicy(config).decide(flow(proxy)), .denyInvalidPolicy)
        config = configuration(); config.tunnel.server = nil
        XCTAssertEqual(GuardPolicy(config).decide(flow(proxy)), .denyInvalidPolicy)
        config = configuration(); config.tunnel.proxy = external
        XCTAssertThrowsError(try config.validate())
        config = configuration(); config.tunnel.server = Endpoint(address: "vpn.example.com", port: 443)
        XCTAssertThrowsError(try config.validate())
    }
    func testPersistenceRoundTripAndCorruptionIsNotOverwritten() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ConfigurationStore(url: directory.appendingPathComponent("draft.json"))
        XCTAssertFalse(try store.load().readinessProblems().isEmpty)
        let config = configuration(); try store.save(config); XCTAssertEqual(try store.load(), config)
        let bytes = Data("{broken".utf8); try bytes.write(to: store.url)
        XCTAssertThrowsError(try store.load()); XCTAssertEqual(try Data(contentsOf: store.url), bytes)
    }
    func testInvalidSaveLeavesPreviousValidConfiguration() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ConfigurationStore(url: directory.appendingPathComponent("draft.json"))
        let config = configuration(); try store.save(config)
        var invalid = config; invalid.services[0].name = ""
        XCTAssertThrowsError(try store.save(invalid)); XCTAssertEqual(try store.load(), config)
    }
    func testBrowserPlanUsesSeparateProfileAndNoDirectFallback() throws {
        let config = configuration(), service = config.services[0]
        let plan = try BrowserLaunchPlan(service: service, proxy: proxy, profilesRoot: URL(fileURLWithPath: "/tmp/Profiles with spaces"))
        XCTAssertEqual(plan.arguments.last, service.website)
        XCTAssertTrue(plan.arguments.contains("--proxy-server=http://127.0.0.1:28761"))
        XCTAssertTrue(plan.arguments.contains("--proxy-bypass-list=<-loopback>"))
        XCTAssertTrue(plan.arguments.contains("--disable-quic"))
        XCTAssertFalse(plan.arguments.contains { $0.contains("direct://") || $0 == "--no-proxy-server" })
        XCTAssertTrue(plan.profileDirectory.path.hasSuffix(service.id.uuidString))
        XCTAssertFalse(FileManager.default.fileExists(atPath: plan.profileDirectory.path))
        var second = service; second.id = UUID()
        XCTAssertNotEqual(try BrowserLaunchPlan(service: second, proxy: proxy, profilesRoot: plan.profileDirectory.deletingLastPathComponent()).profileDirectory, plan.profileDirectory)
    }
    func testUnsupportedBrowserDoesNotGetPretendProxySettings() throws {
        var service = configuration().services[0]; service.browser?.signingIdentifier = "com.apple.Safari"
        XCTAssertThrowsError(try BrowserLaunchPlan(service: service, proxy: proxy, profilesRoot: URL(fileURLWithPath: "/tmp/profiles")))
        service.browser = nil
        XCTAssertThrowsError(try BrowserLaunchPlan(service: service, proxy: proxy, profilesRoot: URL(fileURLWithPath: "/tmp/profiles")))
    }
    func testKernelIdentityRejectsInventedAuditTokens() {
        XCTAssertThrowsError(try CodeIdentity.resolve(auditToken: Data()))
        XCTAssertThrowsError(try CodeIdentity.resolve(auditToken: Data(repeating: 0, count: 32)))
    }
    func testTunnelEditorPreservesIPv6OnUnchangedSave() throws {
        var config = configuration()
        config.tunnel.proxy = Endpoint(address: "::1", port: 30000)
        let draft = TunnelEditorDraft(config.tunnel)
        let saved = try draft.settings()
        XCTAssertEqual(saved, config.tunnel)
        let plan = try BrowserLaunchPlan(service: config.services[0], proxy: saved.proxy,
                                         profilesRoot: URL(fileURLWithPath: "/tmp/profiles"))
        XCTAssertTrue(plan.arguments.contains("--proxy-server=http://[::1]:30000"))
        XCTAssertEqual(GuardPolicy(config).decide(flow(saved.proxy)), .allowProxy)
        XCTAssertEqual(GuardPolicy(config).decide(flow(proxy)), .denyDirect)
        var invalid = draft; invalid.proxyPort = "invalid"
        XCTAssertThrowsError(try invalid.settings())
    }
    func testStaleServiceEditCannotModifyNeighborAfterRemoval() {
        var config = configuration()
        let second = Service(name: "Second", website: "https://second.example.com", browser: browser)
        config.services.append(second)
        var stale = config.services.removeFirst(); stale.name = "Edited after removal"
        XCTAssertFalse(config.updateDraftService(stale))
        XCTAssertEqual(config.services, [second])
        var updated = second; updated.name = "Updated second"
        XCTAssertTrue(config.updateDraftService(updated))
        XCTAssertEqual(config.services, [updated])
    }
    func testMissingNestedRequiredFieldsAreRejected() throws {
        func removingFields<T: Codable>(_ value: T, fields: [String]) throws {
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
            for field in fields {
                var changed = object; changed.removeValue(forKey: field)
                XCTAssertThrowsError(try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: changed)), field)
            }
        }
        try removingFields(configuration().services[0], fields: ["id", "name", "website", "enabled", "programs"])
        try removingFields(configuration().tunnel, fields: ["proxy"])
        try removingFields(proxy, fields: ["address", "port"])
    }

}
