import AuthenticationServices
import CloudKit
import SwiftUI
import MopAppSupport
import MopCore
import MopLocalIdentity

@MainActor final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var passkeyAuthorization: LocalAuthorization?
    private var passkeyRequest: ASPasskeyCredentialRequest?
    private var passkeyParameters: ASPasskeyCredentialRequestParameters?
    private var passkeyRegistration = false
    private var session: AutoFillRequestSession?
    private var task: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?
    private var observations: [AccountObservation] = []
    private var pendingList = false
    private var pendingIdentity: AutoFillIdentity?
    private var retryIdentity: AutoFillIdentity?
    private var retryField: CredentialField?
    #if os(macOS)
    private var focus = AutoFillFocus()
    #endif
    private var generation = 0
    private let model = CredentialListModel()

    override func loadView() {
        let content = CredentialRootView(model: model, passkeyPerform: { [weak self] in self?.performPasskey($0) }, select: { [weak self] in self?.fill($0, field: $1) },
                                         retry: { [weak self] in self?.retry() },
                                         chooseAnother: { [weak self] in self?.prepareList(kind: self?.model.kind) },
                                         cancel: { [weak self] in self?.cancel() })
        #if os(macOS)
        let host = NSHostingController(rootView: content)
        addChild(host); view = host.view
        #else
        let host = UIHostingController(rootView: content)
        view = UIView(); view.backgroundColor = .systemBackground
        addChild(host); host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor), host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor), host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        host.didMove(toParent: self)
        #endif
        observeLifecycle()
        updatePreferredContentSize()
    }
    private func observeLifecycle() {
        guard observations.isEmpty else { return }
        observe(.CKAccountChanged) { [weak self] in
            self?.cancel(); Task { await AutoFillStorage.invalidate() }
        }
        #if os(iOS)
        observe(UIApplication.didEnterBackgroundNotification) { [weak self] in self?.interrupt() }
        #else
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observations.append(AccountObservation(center: center, token: center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.interrupt() }
            }))
        }
        observations.append(AccountObservation(center: center, token: center.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main) { [weak self] note in
            let application = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
            let process = application?.processIdentifier
            Task { @MainActor in
                guard let self, self.session != nil else { return }
                let foreground = Self.userApplication(NSWorkspace.shared.frontmostApplication)
                guard self.focus.shouldInterrupt(activated: process, foreground: foreground) else { return }
                self.interrupt("The active application changed. Retry to authenticate again.")
            }
        }))
        #endif
    }
    private func observe(_ name: Notification.Name, action: @escaping @MainActor @Sendable () -> Void) {
        let center = NotificationCenter.default
        observations.append(AccountObservation(center: center, token: center.addObserver(forName: name, object: nil, queue: .main) { _ in
            Task { @MainActor in action() }
        }))
    }
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.hosts = Set(serviceIdentifiers.compactMap { AutoFillEntry.website($0.identifier) })
        model.textInsertion = false; prepareList(kind: .password)
    }
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.hosts = Set(serviceIdentifiers.compactMap { AutoFillEntry.website($0.identifier) })
        model.textInsertion = false; prepareList(kind: .oneTimeCode)
    }
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        showPasskeys(request: nil, parameters: requestParameters, registration: false)
    }
    #if os(iOS)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        model.hosts = []; model.textInsertion = true; prepareList(kind: nil)
    }
    #endif
    private func prepareList(kind: AutoFillKind?) {
        stop(); pendingIdentity = nil; retryIdentity = nil; retryField = nil
        model.kind = kind; model.showsPicker = true; model.message = nil; model.loading = true
        updatePreferredContentSize()
        guard isViewLoaded, view.window != nil else { pendingList = true; return }
        pendingList = false
        let token = generation
        task = Task {
            do {
                let directory = try AutoFillStorage.directory()
                let identities = try await Task.detached { try AutoFillIndex(directory: directory).load() }.value
                    .filter { kind == nil || $0.kind == kind }
                guard token == generation, !Task.isCancelled else { return }
                guard !identities.isEmpty else {
                    model.loading = false
                    model.message = "No suggestions are available. Open 2ndPass, unlock it, then choose Settings → AutoFill → Refresh Suggestions."
                    updatePreferredContentSize(); return
                }
                let session = beginSession()
                let choices = try await session.choices(for: identities)
                guard token == generation, !Task.isCancelled else { return }
                model.entries = choices.sorted { ($0.identity.website, $0.identity.username, $0.vaultName, $0.itemName, $0.id) < ($1.identity.website, $1.identity.username, $1.vaultName, $1.itemName, $1.id) }
                model.loading = false
                if session.unavailableVaults > 0 { model.message = "Some vaults are unavailable. Open and unlock 2ndPass to refresh them. Available accounts are listed below." }
                else if choices.isEmpty { model.message = "These suggestions are no longer available. Refresh Suggestions in 2ndPass’s AutoFill settings." }
                updatePreferredContentSize()
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                failure(error)
            }
        }
    }
    private func beginSession() -> AutoFillRequestSession {
        session?.end(); expiryTask?.cancel()
        #if os(macOS)
        focus.begin(application: Self.userApplication(NSWorkspace.shared.frontmostApplication))
        #endif
        let value = AutoFillRequestSession(); session = value
        let token = generation
        expiryTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(60)) } catch { return }
            guard let self, self.generation == token else { return }
            self.stop(); self.model.message = "AutoFill timed out. Authenticate again to continue."; self.updatePreferredContentSize()
        }
        return value
    }
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        requireInteraction()
    }
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) { requireInteraction() }
    private func requireInteraction() {
        stop()
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        if let request = credentialRequest as? ASPasskeyCredentialRequest {
            showPasskeys(request: request, parameters: nil, registration: false); return
        }
        guard let identity = AutoFillIdentity(identity: credentialRequest.credentialIdentity) else { identityNotFound(); return }
        prepare(identity)
    }
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        guard let identity = AutoFillIdentity(identity: credentialIdentity) else { identityNotFound(); return }
        prepare(identity)
    }
    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest else { identityNotFound(); return }
        showPasskeys(request: request, parameters: nil, registration: true)
    }
    private func showPasskeys(request: ASPasskeyCredentialRequest?, parameters: ASPasskeyCredentialRequestParameters?, registration: Bool) {
        stop()
        passkeyRequest = request; passkeyParameters = parameters; passkeyRegistration = registration
        guard let rp = parameters?.relyingPartyIdentifier ?? (request?.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier else { identityNotFound(); return }
        model.passkeyRP = rp; model.passkeyRegistration = registration; model.loading = false; model.message = nil
        do {
            let allowed = parameters?.allowedCredentials ?? (request.flatMap { $0.credentialIdentity as? ASPasskeyCredentialIdentity }.map { [$0.credentialID] } ?? [])
            model.passkeys = try LocalIdentityStore.open().list().filter { LocalWebAuthn.matches($0, relyingParty: rp, allowedCredentials: allowed) }
            if !LocalIdentityStore.isAvailable { model.message = "Secure Enclave is unavailable on this device." }
        } catch { model.message = String(describing: error) }
        preferredContentSize = .init(width: 480, height: 480)
    }
    private func performPasskey(_ id: UUID?) {
        guard !model.loading, let rp = model.passkeyRP, LocalIdentityStore.isAvailable else { return }
        let request = passkeyRequest, parameters = passkeyParameters, registration = passkeyRegistration
        let token = generation
        model.loading = true; model.message = nil
        task = Task {
            var authorization: LocalAuthorization?
            defer { authorization?.revoke(); if generation == token { passkeyAuthorization = nil; model.loading = false } }
            do {
                let store = try LocalIdentityStore.open()
                let auth = try await LocalAuthorization.authorizeAsync(reason: registration ? "create a device-bound passkey for \(rp)" : "sign in to \(rp)", ids: id.map { [$0] } ?? [], purposes: [.webauthn], operations: registration ? [.create] : [.passkey])
                authorization = auth
                guard token == generation, !Task.isCancelled else { return }
                passkeyAuthorization = auth
                if registration {
                    guard let request, let credential = request.credentialIdentity as? ASPasskeyCredentialIdentity else { throw MopError.invalidLocalIdentity }
                    let identity = try store.registerPasskey(relyingParty: rp, userName: credential.userName, userHandle: credential.userHandle, clientDataHash: request.clientDataHash, supportedAlgorithms: request.supportedAlgorithms.map { Int($0.rawValue) }, authorization: auth)
                    guard case .passkey(let metadata) = identity.metadata else { throw MopError.invalidLocalIdentity }
                    let response = ASPasskeyRegistrationCredential(relyingParty: rp, clientDataHash: request.clientDataHash, credentialID: metadata.credentialID, attestationObject: try LocalWebAuthn.attestation(metadata: metadata, publicKey: identity.publicKey))
                    guard token == generation, !Task.isCancelled, auth.isActive else { return }
                    if let suggestion = identity.passkeySuggestion {
                        try await ASCredentialIdentityStore.shared.saveCredentialIdentities([suggestion])
                    }
                    guard token == generation, !Task.isCancelled, auth.isActive else { return }
                    // Keep the local record if the platform rejects delivery: never destroy a key
                    // that a relying party may already have registered. It can be deleted in local.
                    extensionContext.completeRegistrationRequest(using: response) { _ in }
                } else {
                    guard let id, let hash = parameters?.clientDataHash ?? request?.clientDataHash else { throw MopError.invalidLocalIdentity }
                    let allowed = parameters?.allowedCredentials ?? (request.flatMap { $0.credentialIdentity as? ASPasskeyCredentialIdentity }.map { [$0.credentialID] } ?? [])
                    let result = try store.assertPasskey(id: id, relyingParty: rp, allowedCredentials: allowed, clientDataHash: hash, authorization: auth)
                    guard token == generation, !Task.isCancelled, auth.isActive else { return }
                    extensionContext.completeAssertionRequest(using: ASPasskeyAssertionCredential(userHandle: result.metadata.userHandle, relyingParty: rp, signature: result.signature, clientDataHash: hash, authenticatorData: result.authenticatorData, credentialID: result.metadata.credentialID), completionHandler: nil)
                }
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                model.message = "Passkey operation failed: \(error). Device-bound passkeys require the platform to accept BE=0 and BS=0."
            }
        }
    }
    private func prepare(_ identity: AutoFillIdentity) {
        stop(); retryIdentity = identity; pendingIdentity = identity
        model.kind = identity.kind; model.showsPicker = false; model.textInsertion = false
        model.message = nil; model.loading = true
        updatePreferredContentSize()
        if isViewLoaded, view.window != nil { pendingIdentity = nil; fill(identity) }
    }
    #if os(macOS)
    override func viewDidAppear() {
        super.viewDidAppear()
        if let identity = pendingIdentity { pendingIdentity = nil; fill(identity) }
        else if pendingList { prepareList(kind: model.kind) }
    }
    override func viewDidDisappear() { super.viewDidDisappear(); stop() }
    #else
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if let identity = pendingIdentity { pendingIdentity = nil; fill(identity) }
        else if pendingList { prepareList(kind: model.kind) }
    }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if isBeingDismissed || isMovingFromParent { stop() }
    }
    #endif
    private func updatePreferredContentSize() {
        #if os(macOS)
        preferredContentSize = model.showsPicker ? NSSize(width: 480, height: 540) : NSSize(width: 440, height: model.message == nil ? 180 : 320)
        #endif
    }
    private func fill(_ identity: AutoFillIdentity, field: CredentialField? = nil) {
        guard !model.loading || session == nil else { return }
        task?.cancel()
        retryIdentity = identity; retryField = field
        model.message = nil; model.loading = true
        let value = session ?? beginSession()
        let token = generation
        task = Task {
            do {
                if identity.kind == .oneTimeCode {
                    let result = try await value.code(identity)
                    guard token == generation, !Task.isCancelled else { return }
                    guard result.expiresAt > Date() else { throw MopError.invalidOTP }
                    await value.recordDeliveredUsage()
                    guard token == generation, !Task.isCancelled else { return }
                    finish()
                    #if os(iOS)
                    if field == .code { extensionContext.completeRequest(withTextToInsert: result.credential.code, completionHandler: nil); return }
                    #endif
                    extensionContext.completeOneTimeCodeRequest(using: result.credential, completionHandler: nil)
                } else {
                    let credential = try await value.password(identity)
                    guard token == generation, !Task.isCancelled else { return }
                    await value.recordDeliveredUsage()
                    guard token == generation, !Task.isCancelled else { return }
                    finish()
                    #if os(iOS)
                    if let field {
                        extensionContext.completeRequest(withTextToInsert: field == .username ? credential.user : credential.password, completionHandler: nil); return
                    }
                    #endif
                    extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
                }
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                failure(error)
            }
        }
    }
    private func retry() {
        if let identity = retryIdentity { fill(identity, field: retryField) }
        else { prepareList(kind: model.kind) }
    }
    private func failure(_ error: Error) {
        finish(); model.loading = false
        switch error as? MopError {
        case .authentication: model.message = "Authentication was cancelled. Retry when you are ready."
        case .notFound, .vaultMissing: model.message = "This account was changed or removed. Choose another account, or refresh suggestions in 2ndPass."
        case .deviceRemoved, .deviceRemovalPending, .notVaultMember: model.message = "This device is no longer connected to the vault. Open 2ndPass and reconnect before trying again."
        case .invalidIdentity, .signing: model.message = "AutoFill needs setup. Open 2ndPass, connect this device, then enable 2ndPass in Settings → AutoFill."
        case .invalidOTP: model.message = "The verification code expired or is unavailable. Retry to generate a fresh code."
        default:
            model.message = error is AutoFillSessionError ? "AutoFill timed out. Retry to authenticate again." : "This vault is unavailable. Retry, choose another account, or open and unlock 2ndPass to refresh it."
        }
        updatePreferredContentSize()
    }
    private func finish() {
        session?.end(); session = nil; expiryTask?.cancel(); expiryTask = nil
        model.entries = []; model.loading = false
    }
    private func stop() {
        passkeyAuthorization?.revoke(); passkeyAuthorization = nil; passkeyRequest = nil; passkeyParameters = nil
        model.passkeyRP = nil; model.passkeys = []
        generation += 1; task?.cancel(); task = nil; pendingIdentity = nil; pendingList = false; finish()
    }
    #if os(macOS)
    private static func userApplication(_ application: NSRunningApplication?) -> pid_t? {
        guard let application, application.activationPolicy == .regular,
              application.processIdentifier != ProcessInfo.processInfo.processIdentifier,
              application.bundleIdentifier != "com.apple.SecurityAgent",
              application.bundleIdentifier != "com.apple.CoreAuthUI" else { return nil }
        return application.processIdentifier
    }
    #endif
    private func interrupt(_ reason: String = "AutoFill paused because the device locked, slept, or the request entered the background. Retry to authenticate again.") {
        guard session != nil || model.passkeyRP != nil else { return }
        stop(); model.message = reason; updatePreferredContentSize()
    }
    private func identityNotFound() {
        stop(); model.message = "This suggestion is no longer available. Choose another account."; updatePreferredContentSize()
    }
    private func cancel() {
        stop(); extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }
}

private enum CredentialField { case username, password, code }
@MainActor @Observable private final class CredentialListModel {
    var passkeyRP: String?
    var passkeyRegistration = false
    var passkeys: [LocalIdentity] = []
    var showsPicker = false
    var textInsertion = false
    var kind: AutoFillKind? = .password
    var entries: [AutoFillChoice] = []
    var hosts: Set<String> = []
    var loading = true
    var message: String?
}

private struct CredentialRootView: View {
    @Bindable var model: CredentialListModel
    let passkeyPerform: (UUID?) -> Void
    let select: (AutoFillIdentity, CredentialField?) -> Void
    let retry: () -> Void
    let chooseAnother: () -> Void
    let cancel: () -> Void
    var body: some View {
        if let rp = model.passkeyRP {
            LocalPasskeyPrompt(relyingParty: rp, registration: model.passkeyRegistration, identities: model.passkeys, busy: model.loading, message: model.message, perform: passkeyPerform, cancel: cancel)
        } else {
            CredentialListView(model: model, select: select, retry: retry, chooseAnother: chooseAnother, cancel: cancel)
        }
    }
}

private struct CredentialListView: View {
    @Bindable var model: CredentialListModel
    let select: (AutoFillIdentity, CredentialField?) -> Void
    let retry: () -> Void
    let chooseAnother: () -> Void
    let cancel: () -> Void
    @State private var search = ""
    @State private var showsOtherAccounts = false
    @State private var selection: String?
    @State private var unrelated: AutoFillChoice?
    @State private var insertionField: CredentialField?
    @FocusState private var searchFocused: Bool
    private var filtered: [AutoFillChoice] {
        model.entries.filter { search.isEmpty || [$0.identity.website, $0.identity.username, $0.itemName, $0.vaultName].contains { $0.localizedCaseInsensitiveContains(search) } }
    }
    private var ordered: [AutoFillChoice] {
        matching + (model.hosts.isEmpty || showsOtherAccounts ? other : [])
    }
    private var matching: [AutoFillChoice] { filtered.filter { model.hosts.contains($0.identity.website) } }
    private var other: [AutoFillChoice] { filtered.filter { !model.hosts.contains($0.identity.website) } }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Text("2ndPass AutoFill").font(.headline); Spacer(); Button("Cancel", action: cancel).keyboardShortcut(.cancelAction) }
            if !model.hosts.isEmpty { Text("Filling for " + model.hosts.sorted().joined(separator: ", ")).font(.callout) }
            if model.loading { ProgressView("Authenticating for AutoFill…") }
            if let message = model.message {
                Text(message).font(.callout).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Retry", action: retry).disabled(model.loading)
                    Button("Choose Another Account", action: chooseAnother).disabled(model.loading)
                }
            }
            if model.showsPicker && !model.entries.isEmpty {
                TextField("Search accounts, websites, or vaults", text: $search).textFieldStyle(.roundedBorder).focused($searchFocused)
                    .onSubmit { fillSelected() }
                    .onKeyPress(.downArrow) { moveSelection(1); return .handled }
                    .onKeyPress(.upArrow) { moveSelection(-1); return .handled }
                if !model.hosts.isEmpty {
                    if !model.entries.contains(where: { model.hosts.contains($0.identity.website) }) {
                        Text("No accounts match this website exactly.").foregroundStyle(.secondary)
                    }
                    Button(showsOtherAccounts ? "Hide other accounts" : "Show other accounts") {
                        showsOtherAccounts.toggle()
                        selection = ordered.first?.id
                    }
                }
                if ordered.isEmpty {
                    if !search.isEmpty { ContentUnavailableView.search(text: search) }
                }
                else {
                    List(selection: $selection) {
                        if !model.hosts.isEmpty { section("For This Website", entries: matching) }
                        if model.hosts.isEmpty || showsOtherAccounts {
                            section(model.hosts.isEmpty ? "Accounts" : "Other Accounts", entries: other)
                        }
                    }
                    .onKeyPress(.return) { fillSelected(); return .handled }
                    if !model.textInsertion {
                        Button("Fill") { fillSelected() }.keyboardShortcut(.defaultAction).disabled(selection == nil || model.loading)
                    }
                }
            }
        }.padding().frame(minWidth: 280, minHeight: model.showsPicker ? 300 : 120)
        .onChange(of: model.entries) { _, _ in
            selection = ordered.first?.id; searchFocused = !model.entries.isEmpty
            if model.entries.isEmpty { unrelated = nil; search = ""; showsOtherAccounts = false }
        }
        .onChange(of: model.hosts) { _, _ in
            showsOtherAccounts = false; unrelated = nil; selection = ordered.first?.id
        }
        .onChange(of: search) { _, _ in selection = ordered.first?.id }
        .confirmationDialog("Use this account for another website?", isPresented: Binding(get: { unrelated != nil }, set: { if !$0 { unrelated = nil } }), titleVisibility: .visible) {
            if let unrelated { Button("Fill Account") { select(unrelated.identity, insertionField); self.unrelated = nil } }
            Button("Cancel", role: .cancel) { unrelated = nil }
        } message: {
            if let unrelated { Text("The requested site is \(model.hosts.sorted().joined(separator: ", ")). This account is for \(unrelated.identity.website): \(unrelated.identity.username) — \(unrelated.itemName), \(unrelated.vaultName).") }
        }
    }
    @ViewBuilder private func section(_ title: String, entries: [AutoFillChoice]) -> some View {
        if !entries.isEmpty {
            Section(title) {
                ForEach(entries) { entry in
                    VStack(alignment: .leading, spacing: 5) {
                        Text(entry.itemName).font(.headline)
                        Text(entry.identity.website + " · " + entry.identity.username)
                        Text(entry.vaultName).font(.caption).foregroundStyle(.secondary)
                        if model.textInsertion {
                            HStack {
                                if entry.identity.kind == .oneTimeCode { Button("Code") { choose(entry, field: .code) } }
                                else {
                                    Button("Username") { choose(entry, field: .username) }
                                    Button("Password") { choose(entry, field: .password) }
                                }
                            }.buttonStyle(.bordered)
                        }
                    }.tag(entry.id).contentShape(Rectangle())
                    .onTapGesture { selection = entry.id; if !model.textInsertion { choose(entry) } }
                    .accessibilityElement(children: .contain)
                    .accessibilityAction(named: "Fill") { choose(entry) }
                }
            }
        }
    }
    private func choose(_ entry: AutoFillChoice, field: CredentialField? = nil) {
        guard !model.loading else { return }
        if !model.hosts.isEmpty && !model.hosts.contains(entry.identity.website) { insertionField = field; unrelated = entry }
        else { select(entry.identity, field) }
    }
    private func fillSelected() {
        guard let entry = ordered.first(where: { $0.id == selection }) else { return }
        choose(entry, field: model.textInsertion ? (entry.identity.kind == .oneTimeCode ? .code : .password) : nil)
    }
    private func moveSelection(_ offset: Int) {
        guard !ordered.isEmpty else { return }
        let index = ordered.firstIndex { $0.id == selection } ?? 0
        selection = ordered[min(ordered.count - 1, max(0, index + offset))].id
    }
}

private final class AccountObservation: @unchecked Sendable {
    let center: NotificationCenter
    let token: NSObjectProtocol
    init(center: NotificationCenter, token: NSObjectProtocol) { self.center = center; self.token = token }
    deinit { center.removeObserver(token) }
}
