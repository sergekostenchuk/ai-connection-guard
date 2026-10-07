import AppKit
import SwiftUI
import UniformTypeIdentifiers
import ConnectionGuardCore

@MainActor
final class GuardModel: ObservableObject {
    @Published var configuration = GuardConfiguration()
    @Published var selectedService: UUID?
    @Published var message: String?
    @Published var loadFailure: String?
    private let store: ConfigurationStore
    init(storeURL: URL? = nil) {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AI Connection Guard", isDirectory: true)
        store = ConfigurationStore(url: storeURL ?? directory.appendingPathComponent("draft.json"))
        do { configuration = try store.load() }
        catch { loadFailure = "Настройки не прочитаны: \(error.localizedDescription). Исходный файл сохранён." }
        selectedService = configuration.services.first?.id
    }
    func save() {
        guard loadFailure == nil else { return }
        do { try store.save(configuration); message = "Настройки сохранены. Сетевые ограничения не применялись." }
        catch { message = error.localizedDescription }
    }
    func addService(name: String, website: String) throws {
        var updated = configuration
        let service = Service(name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                              website: website.trimmingCharacters(in: .whitespacesAndNewlines))
        updated.services.append(service)
        try updated.validate()
        configuration = updated; selectedService = service.id
    }
    func chooseProgram(kind: TargetKind) -> ProgramTarget? {
        let panel = NSOpenPanel()
        panel.title = kind == .browser ? "Выберите отдельный браузер" : "Выберите программу"
        panel.canChooseDirectories = false; panel.canChooseFiles = true; panel.allowsMultipleSelection = false
        if kind != .executable { panel.allowedContentTypes = [.applicationBundle] }
        panel.directoryURL = URL(fileURLWithPath: kind == .executable ? NSHomeDirectory() : "/Applications")
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        do { return try CodeIdentity.enroll(url: url, kind: kind) }
        catch { message = error.localizedDescription; return nil }
    }
    func importDraft() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let draft = try ConfigurationStore(url: url).load()
            configuration = draft; selectedService = draft.services.first?.id
            // Keep a damaged original intact; an imported replacement is saved explicitly by the user.
            loadFailure = nil; message = "Настройки загружены в редактор. Для записи нажмите «Сохранить настройки»."
        } catch { message = error.localizedDescription }
    }
    func exportDraft() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "connection-guard.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try ConfigurationStore(url: url).save(configuration); message = "Настройки экспортированы." }
        catch { message = error.localizedDescription }
    }
}

struct SettingsView: View {
    @ObservedObject var model: GuardModel
    @State private var addingService = false
    @State private var editingTunnel = false
    @State private var showingSimulation = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled").font(.system(size: 30)).foregroundColor(.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text("AI Connection Guard").font(.title2.bold())
                    Text(BuildSafety.status).foregroundColor(.secondary)
                }
                Spacer()
            }
            Text("Здесь можно подготовить сервисы, браузеры и режим для поездок. Эта сборка не устанавливает фильтр, не запускает туннель и не меняет действующие подключения.")
                .font(.callout).fixedSize(horizontal: false, vertical: true)
            if let error = model.loadFailure { Text(error).foregroundColor(.red).font(.callout) }
            HStack {
                Text("Режим после будущего подключения:")
                Picker("Режим", selection: $model.configuration.mode) {
                    ForEach(DesiredMode.allCases, id: \.self) { Text($0.title).tag($0) }
                }.labelsHidden().frame(maxWidth: 300)
                Spacer()
            }
            HSplitView {
                VStack(alignment: .leading) {
                    List(selection: $model.selectedService) {
                        ForEach(model.configuration.services) { service in
                            HStack {
                                Image(systemName: service.enabled ? "checkmark.shield" : "shield.slash")
                                VStack(alignment: .leading) {
                                    Text(service.name)
                                    Text(service.enabled ? "В списке защиты" : "Без защиты").font(.caption).foregroundColor(.secondary)
                                }
                            }.padding(.vertical, 4).tag(service.id)
                        }
                    }.frame(minWidth: 170)
                    Button { addingService = true } label: { Label("Добавить сервис", systemImage: "plus") }.padding(.top, 4)
                }.frame(minWidth: 180, idealWidth: 205, maxWidth: 250)
                if let index = model.configuration.services.firstIndex(where: { $0.id == model.selectedService }) {
                    ServiceEditor(model: model, service: serviceBinding(model.configuration.services[index]))
                        .id(model.configuration.services[index].id).frame(minWidth: 430)
                } else {
                    Text("Добавьте или выберите сервис").foregroundColor(.secondary).frame(maxWidth: .infinity)
                }
            }.frame(minHeight: 310)
            Divider()
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Локальный туннель").font(.headline)
                    Text(model.configuration.tunnel.server.map { "Сервер: \($0.address):\($0.port)" } ?? "Сервер ещё не настроен")
                        .font(.caption).foregroundColor(.secondary)
                }
                Spacer()
                Button("Настройки туннеля…") { editingTunnel = true }
                Button("Проверить правило…") { showingSimulation = true }
            }
            if let message = model.message { Text(message).font(.callout).foregroundColor(.secondary).textSelection(.enabled) }
            HStack {
                Button("Импорт…") { model.importDraft() }
                Button("Экспорт…") { model.exportDraft() }
                Spacer()
                Button("Применить защиту") { model.message = GuardError.preparationOnly.localizedDescription }
                    .disabled(true).help("Подключение системного фильтра выполняется отдельно после подписания и проверки.")
                Button("Сохранить настройки") { model.save() }.keyboardShortcut("s").disabled(model.loadFailure != nil)
            }
        }
        .padding(24).frame(minWidth: 850, minHeight: 680)
        .background(Color(NSColor.windowBackgroundColor))
        .sheet(isPresented: $addingService) { AddServiceView(model: model) }
        .sheet(isPresented: $editingTunnel) { TunnelView(model: model) }
        .sheet(isPresented: $showingSimulation) { SimulationView(configuration: model.configuration) }
    }
    private func serviceBinding(_ snapshot: Service) -> Binding<Service> {
        // SwiftUI can read a child binding during its removal animation. Resolve by stable ID,
        // never by the array index of a service that may already have been deleted/imported.
        Binding(get: { model.configuration.services.first { $0.id == snapshot.id } ?? snapshot },
                set: { updated in
                    guard updated.id == snapshot.id else { return }
                    model.configuration.updateDraftService(updated)
                })
    }
}

struct ServiceEditor: View {
    @ObservedObject var model: GuardModel
    @Binding var service: Service
    @State private var confirmingRemoval = false
    @State private var browserPlan: String?
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                TextField("Название", text: $service.name).font(.title3.bold())
                Toggle("Включить сервис в список защиты", isOn: $service.enabled)
                TextField("Сайт сервиса · https://…", text: $service.website)
                Text("Приложения и CLI").font(.headline)
                if service.programs.isEmpty { Text("Программы не выбраны").foregroundColor(.secondary) }
                ForEach(service.programs) { target in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(URL(fileURLWithPath: target.path).lastPathComponent)
                            Text(target.path).font(.caption).foregroundColor(.secondary).textSelection(.enabled)
                        }
                        Spacer()
                        Button { service.programs.removeAll { $0.id == target.id } } label: { Image(systemName: "minus.circle") }
                            .help("Убрать программу из сервиса").accessibilityLabel("Убрать \(target.path)")
                    }
                }
                HStack {
                    Button("Добавить приложение…") { addProgram(.application) }
                    Button("Добавить CLI…") { addProgram(.executable) }
                }
                Divider()
                Text("Подключение через браузер").font(.headline)
                if let browser = service.browser {
                    Text(URL(fileURLWithPath: browser.path).lastPathComponent)
                    Text(browser.path).font(.caption).foregroundColor(.secondary).textSelection(.enabled)
                    Text(BrowserLaunchPlan.supports(browser) ? "Подготовка запуска через прокси поддерживается" : "Для этого браузера прокси нужно будет настроить отдельно")
                        .font(.caption).foregroundColor(.secondary)
                    let shared = model.configuration.browserSharing(browser)
                    if shared.count > 1 {
                        Text("Общий браузер: \(shared.joined(separator: ", ")). Он остаётся в списке защиты, пока включён хотя бы один из этих сервисов.")
                            .font(.callout).foregroundColor(.orange)
                    }
                } else { Text("Браузер не выбран").foregroundColor(.secondary) }
                HStack {
                    Button(service.browser == nil ? "Выбрать браузер…" : "Сменить браузер…") {
                        if let target = model.chooseProgram(kind: .browser) { service.browser = target }
                    }
                    if service.browser != nil { Button("Убрать браузер") { service.browser = nil } }
                }
                if service.browser != nil {
                    Button("Посмотреть параметры запуска…") {
                        do {
                            let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                                .appendingPathComponent("AI Connection Guard/Browser Profiles")
                            let plan = try BrowserLaunchPlan(service: service, proxy: model.configuration.tunnel.proxy, profilesRoot: root)
                            browserPlan = "Браузер: \(plan.applicationPath)\n\nАргументы:\n" + plan.arguments.joined(separator: "\n")
                        } catch { browserPlan = error.localizedDescription }
                    }
                }
                Text("Защита охватывает весь выбранный браузер, включая все профили и вкладки. Для AI-сервисов выделите отдельный браузер. Адрес сайта нужен для сервиса; он не ограничивает остальные вкладки.")
                    .font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                Divider()
                Button("Удалить сервис…", role: .destructive) { confirmingRemoval = true }
            }.padding(.leading, 20).padding(.trailing, 8).padding(.vertical, 6)
        }
        .sheet(isPresented: Binding(get: { browserPlan != nil }, set: { if !$0 { browserPlan = nil } })) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Параметры будущего запуска").font(.title2)
                Text("Браузер не запущен. Профиль не создан. Параметры рассчитаны для защищённого режима; применять их можно после подключения фильтра и туннеля.").foregroundColor(.secondary)
                ScrollView { Text(browserPlan ?? "").font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                Button("Закрыть") { browserPlan = nil }
            }.padding(24).frame(width: 610, height: 400)
        }
        .alert("Удалить \(service.name) из настроек?", isPresented: $confirmingRemoval) {
            Button("Удалить", role: .destructive) {
                let id = service.id
                model.selectedService = nil
                model.configuration.services.removeAll { $0.id == id }
            }
            Button("Отмена", role: .cancel) {}
        } message: { Text("Изменение затронет только подготовленные настройки.") }
    }
    private func addProgram(_ kind: TargetKind) {
        if let target = model.chooseProgram(kind: kind), !service.programs.contains(where: { $0.path == target.path }) {
            service.programs.append(target)
        }
    }
}

struct AddServiceView: View {
    @ObservedObject var model: GuardModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var website = "https://"
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Добавить сервис").font(.title2)
            TextField("Название", text: $name)
            TextField("Адрес сайта", text: $website)
            Text("Затем выберите приложение, CLI или браузер для этого сервиса.").foregroundColor(.secondary)
            if let error { Text(error).foregroundColor(.red) }
            HStack {
                Button("Отмена") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Добавить") {
                    do { try model.addService(name: name, website: website); dismiss() }
                    catch { self.error = error.localizedDescription }
                }.keyboardShortcut(.defaultAction)
            }
        }.padding(24).frame(width: 440)
    }
}

struct TunnelView: View {
    @ObservedObject var model: GuardModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = TunnelEditorDraft(TunnelSettings())
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Настройки будущего туннеля").font(.title2)
            Text("Приложения смогут обращаться только к локальному прокси, а Xray — только к указанному серверу.")
            Picker("Адрес локального прокси", selection: $draft.proxyAddress) {
                Text("127.0.0.1 · IPv4").tag("127.0.0.1")
                Text("::1 · IPv6").tag("::1")
            }
            HStack { Text("Порт прокси"); TextField("28761", text: $draft.proxyPort) }
            HStack { Text("IP сервера"); TextField("IPv4 или IPv6", text: $draft.serverAddress) }
            HStack { Text("Порт сервера"); TextField("443", text: $draft.serverPort) }
            Text(draft.process?.path ?? "Исполняемый файл Xray не выбран").font(.caption).textSelection(.enabled)
            Button("Выбрать Xray…") { if let target = model.chooseProgram(kind: .executable) { draft.process = target } }
            Text("Здесь нет паролей и ключей. Проверенный конфиг Xray, запуск туннеля и настройки прокси приложений подключаются при отдельном развёртывании. Эта сборка их не меняет.")
                .font(.callout).foregroundColor(.secondary)
            if let error { Text(error).foregroundColor(.red) }
            HStack {
                Button("Отмена") { dismiss() }
                Spacer()
                Button("Сохранить в настройках") {
                    do {
                        var updated = model.configuration
                        updated.tunnel = try draft.settings()
                        try updated.validate(); model.configuration = updated; dismiss()
                    } catch { self.error = error.localizedDescription }
                }
            }
        }.padding(24).frame(width: 500)
        .onAppear {
            draft = TunnelEditorDraft(model.configuration.tunnel)
        }
    }
}

struct SimulationView: View {
    let configuration: GuardConfiguration
    @Environment(\.dismiss) private var dismiss
    @State private var targetID: UUID?
    @State private var address = "1.1.1.1"
    @State private var port = "443"
    @State private var udp = false
    @State private var result: String?
    private var targets: [ProgramTarget] {
        var seen = Set<UUID>()
        return (configuration.protectedTargets + (configuration.tunnel.process.map { [$0] } ?? []))
            .filter { seen.insert($0.id).inserted }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Проверка правила без подключения").font(.title2)
            Text("Это расчёт решения по настройкам. Он не доказывает работу сетевой защиты на Mac.").foregroundColor(.secondary)
            Picker("Программа", selection: $targetID) {
                Text("Неизвестный процесс").tag(Optional<UUID>.none)
                ForEach(targets) { target in Text(URL(fileURLWithPath: target.path).lastPathComponent).tag(Optional(target.id)) }
            }
            TextField("IP назначения", text: $address)
            TextField("Порт", text: $port)
            Toggle("UDP", isOn: $udp)
            Button("Рассчитать") {
                guard let p = UInt16(port), p > 0 else { result = "Укажите корректный порт."; return }
                let identity = targets.first { $0.id == targetID }.map {
                    VerifiedProcess(executablePath: $0.path, signingIdentifier: $0.signingIdentifier,
                                    teamIdentifier: $0.teamIdentifier, codeHash: $0.codeHash)
                }
                let flow = ConnectionFlow(identities: identity.map { [$0] } ?? [], remote: Endpoint(address: address, port: p),
                                          transport: udp ? .udp : .tcp)
                result = GuardPolicy(configuration).decide(flow).explanation
            }
            if let result { Text(result).textSelection(.enabled) }
            ForEach(configuration.readinessProblems(), id: \.self) { Text($0).font(.caption).foregroundColor(.secondary) }
            HStack { Spacer(); Button("Закрыть") { dismiss() }.keyboardShortcut(.cancelAction) }
        }.padding(24).frame(width: 500)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var window: NSWindow?
    private var model: GuardModel!
    func applicationDidFinishLaunching(_ notification: Notification) {
        model = GuardModel()
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "AI Connection Guard — подготовка")
        item.button?.toolTip = BuildSafety.status
        let menu = NSMenu()
        let status = NSMenuItem(title: BuildSafety.status, action: nil, keyEquivalent: ""); status.isEnabled = false
        menu.addItem(status); menu.addItem(.separator())
        let settings = NSMenuItem(title: "Сервисы и браузеры…", action: #selector(showSettings), keyEquivalent: ",")
        settings.target = self; menu.addItem(settings)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Завершить AI Connection Guard", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit); item.menu = menu
        showSettings()
    }
    @objc func showSettings() {
        if window == nil {
            let controller = NSHostingController(rootView: SettingsView(model: model))
            let result = NSWindow(contentViewController: controller)
            result.title = "AI Connection Guard · настройки"
            result.setContentSize(NSSize(width: 940, height: 760))
            result.styleMask.insert([.resizable, .miniaturizable]); result.isReleasedWhenClosed = false
            result.center(); window = result
        }
        NSApp.activate(ignoringOtherApps: true); window?.makeKeyAndOrderFront(nil)
    }
}

@main
struct Main {
    @MainActor static func main() {
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--render-preview" {
            renderPreview(to: URL(fileURLWithPath: CommandLine.arguments[2])); return
        }
        let delegate = AppDelegate()
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory); app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
    @MainActor private static func renderPreview(to url: URL) {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        app.appearance = NSAppearance(named: .aqua)
        app.finishLaunching()
        let model = GuardModel(storeURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json"))
        let view = NSHostingView(rootView: SettingsView(model: model))
        let frame = NSRect(x: 0, y: 0, width: 1020, height: 800)
        let window = NSWindow(contentRect: frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = view; view.frame = frame
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.2))
        view.layoutSubtreeIfNeeded(); view.displayIfNeeded()
        guard let image = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: image)
        guard let data = image.representation(using: .png, properties: [:]) else { return }
        do { try data.write(to: url) } catch { fputs("Preview: \(error.localizedDescription)\n", stderr) }
        withExtendedLifetime(window) {}
    }
}
