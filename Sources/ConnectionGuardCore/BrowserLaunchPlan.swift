import Foundation

/// Pure launch description. It never launches a browser, creates a profile, or edits browser preferences.
public struct BrowserLaunchPlan: Equatable {
    public let applicationPath: String
    public let profileDirectory: URL
    public let arguments: [String]
    public static func supports(_ browser: ProgramTarget) -> Bool {
        browser.kind == .browser && ["com.google.Chrome", "com.google.Chrome.beta", "com.google.Chrome.canary",
                                    "com.brave.Browser", "com.microsoft.edgemac", "org.chromium.Chromium"]
            .contains(browser.signingIdentifier)
    }
    public init(service: Service, proxy: Endpoint, profilesRoot: URL) throws {
        try service.validate()
        guard let browser = service.browser, Self.supports(browser) else {
            throw GuardError.invalid("Параметры запуска подготовлены для Chrome, Edge, Brave и Chromium. Для другого браузера потребуется отдельная настройка прокси.")
        }
        try TunnelSettings(proxy: proxy).validateDraft()
        guard profilesRoot.isFileURL, profilesRoot.path.hasPrefix("/"), profilesRoot.path != "/" else {
            throw GuardError.invalid("Укажите каталог профилей приложения.")
        }
        applicationPath = browser.path
        profileDirectory = profilesRoot.appendingPathComponent(service.id.uuidString, isDirectory: true)
        let host = proxy.canonicalAddress == "::1" ? "[::1]" : "127.0.0.1"
        arguments = ["--user-data-dir=\(profileDirectory.path)",
                     "--proxy-server=http://\(host):\(proxy.port)",
                     "--proxy-bypass-list=<-loopback>", "--disable-quic", "--new-window", service.website]
    }
}
