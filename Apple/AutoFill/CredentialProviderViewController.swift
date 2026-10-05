import AuthenticationServices
import CloudKit
import SwiftUI
import MopAppSupport
import MopCore
import MopLocalIdentity

@MainActor final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let cloudPasskeyService = ItemVaultService(allowsAttachments: false)
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
        let content = CredentialRootView(model: model, saveLogin: { [weak self] in self?.saveLogin() }, reloadLoginVaults: { [weak self] in self?.loadLoginVaults() }, passkeyPerform: { [weak self] in self?.performPasskey($0, vault: $1) }, select: { [weak self] in self?.fill($0, field: $1) },
                                         retry: { [weak self] in self?.retry() },
                                         chooseAnother: { [weak self] in self?.prepareList(kind: self?.model.kind) },
                                         cancel: { [weak self] in self?.cancel() },
                                         resizePasskey: { [weak self] height in
                                             #if os(macOS)
                                             self?.preferredContentSize = .init(width: 480, height: min(640, max(360, height)))
                                             #endif
                                         })
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
    #if os(iOS)
    @available(iOS 26.2, *)
    override func performWithoutUserInteractionIfPossible(savePasswordRequest: ASSavePasswordRequest) {
        // Every save requires an explicit destination and name confirmation.
        requireInteraction()
    }
    @available(iOS 26.2, *)
    override func prepareInterface(for savePasswordRequest: ASSavePasswordRequest) {
        stop()
        let website = savePasswordRequest.serviceIdentifier.identifier
        model.loginDraft = AutoFillLoginDraft(name: savePasswordRequest.title ?? AutoFillEntry.website(website) ?? website,
            username: savePasswordRequest.credential.user, password: savePasswordRequest.credential.password, website: website)
        model.message = nil
        loadLoginVaults()
    }
    #endif
    private func loadLoginVaults() {
        guard model.loginDraft != nil else { return }
        let token = generation
        model.loading = true; model.message = nil; model.loginVaults = []; model.loginVault = ""
        task = Task {
            defer { if token == generation { model.loading = false } }
            do {
                let result = try await cloudPasskeyService.execute(.discover, vault: nil, offline: false)
                var available: [VaultDescriptor] = []
                var unavailable = false
                for vault in result.vaults where vault.enrolled && vault.supported {
                    do {
                        let catalog = try await cloudPasskeyService.execute(.catalog, vault: vault.id, offline: false).requireCatalog()
                        if catalog.canEdit == true { available.append(vault) }
                    } catch { unavailable = true }
                    guard token == generation, !Task.isCancelled else { return }
                }
                guard token == generation, !Task.isCancelled else { return }
                model.loginVaults = available
                if available.isEmpty { model.message = "No writable vaults are available. Open 2ndPass to connect a vault, then try again." }
                else if unavailable { model.message = "Some vaults could not be opened. You can retry or choose an available vault." }
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                model.message = "Vaults could not be loaded. Try again."
            }
        }
    }
    private func saveLogin() {
        #if os(iOS)
        guard #available(iOS 26.2, *), !model.loading, let draft = model.loginDraft,
              draft.canSave, model.loginVaults.contains(where: { $0.id == model.loginVault }) else { return }
        let token = generation, vault = model.loginVault
        model.loading = true; model.message = nil
        task = Task {
            defer { if token == generation { model.loading = false } }
            do {
                let catalog = try await draft.save(vault: vault, service: cloudPasskeyService)
                guard token == generation, !Task.isCancelled else { return }
                // Saving succeeded even if the system's suggestion store is unavailable.
                // The containing app can refresh that public index later.
                try? await AutoFillPublisher.shared.publish(catalog: catalog, vaultID: vault)
                guard token == generation, !Task.isCancelled else { return }
                model.loginDraft = nil; cloudPasskeyService.lock()
                extensionContext.completeSavePasswordRequest(completionHandler: nil)
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                if let failure = error as? MopError, case .duplicate = failure {
                    model.message = "A login with this name already exists. Choose a different name to save a new login."
                } else { model.message = error.localizedDescription }
            }
        }
        #endif
    }
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
                // Browsing uses only published metadata. Start authentication and its
                // timeout when a credential is selected, never while listing accounts.
                model.entries = identities.sorted { ($0.website, $0.username, $0.id) < ($1.website, $1.username, $1.id) }
                model.loading = false
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
        let token = generation
        model.loading = true
        task = Task {
            do {
                let allowed = parameters?.allowedCredentials ?? (request.flatMap { $0.credentialIdentity as? ASPasskeyCredentialIdentity }.map { [$0.credentialID] } ?? [])
                if registration {
                    let discovery = try await CloudCredentialService(cloudPasskeyService).discoverPasskeys(
                        relyingParty: rp, allowed: allowed, registration: true)
                    guard token == generation, !Task.isCancelled else { return }
                    model.passkeyVaults = discovery.vaults
                    if discovery.unavailableVaults > 0 {
                        model.message = "Some cloud vaults could not be opened. Available vaults are shown."
                    }
                } else {
                    // Browsing must never open vaults or ask for authentication.
                    let directory = try AutoFillStorage.directory()
                    let entries = try await Task.detached { try AutoFillIndex(directory: directory).load() }.value
                    guard token == generation, !Task.isCancelled else { return }
                    model.cloudPasskeys = entries.filter { $0.matchesPasskey(relyingParty: rp, allowed: allowed) }
                    // Discovery is complete: only skip the chooser when the combined
                    // cloud/device-local result is unambiguous. Use the normal signing
                    // path so fresh verification and live access checks still apply.
                    model.loading = false
                    if model.passkeys.count + model.cloudPasskeys.count == 1 {
                        if let identity = model.passkeys.first {
                            performPasskey(identity.id.uuidString, vault: LocalVault.id)
                        } else if let identity = model.cloudPasskeys.first,
                                  let vault = AutoFillEntry.vaultID(identity.recordIdentifier) {
                            performPasskey(identity.id, vault: vault)
                        }
                        return
                    }
                }
            } catch {
                guard token == generation else { return }
                model.message = "Cloud passkeys could not be loaded: \(error.localizedDescription). Device-local credentials remain available."
            }
            if token == generation { model.loading = false }
        }
        preferredContentSize = .init(width: 480, height: 400)
    }
    private func performPasskey(_ selection: String?, vault: String) {
        if !LocalVault.isLocal(vault) { performCloudPasskey(selection, vault: vault); return }
        let id = selection.flatMap(UUID.init(uuidString:))
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
                    try await AutoFillPublisher.shared.refreshLocalPasskeys()
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
                model.message = "Device-local passkey operation failed: \(error). This platform or website may not accept device-bound passkeys. A credential created under the earlier backup-flag override may require re-registration."
            }
        }
    }
    private func performCloudPasskey(_ selection: String?, vault: String) {
        guard !model.loading, let rp = model.passkeyRP else { return }
        let request = passkeyRequest, parameters = passkeyParameters, registration = passkeyRegistration, token = generation
        model.loading = true; model.message = nil
        // One fresh vault authentication both verifies the user and unlocks the
        // device key. A separate LocalAuthorization would prompt a second time.
        cloudPasskeyService.lock()
        let vaultGeneration = cloudPasskeyService.sessionGeneration
        task = Task {
            defer {
                if token == generation { cloudPasskeyService.lock(); model.loading = false }
            }
            do {
                guard token == generation, !Task.isCancelled else { return }
                let provider = CloudCredentialService(cloudPasskeyService)
                if registration {
                    guard let request, let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else { throw CredentialFailure.invalid }
                    let row = try await provider.registerPasskey(vault: vault, relyingParty: rp, userName: identity.userName, userHandle: identity.userHandle, clientDataHash: request.clientDataHash, algorithms: request.supportedAlgorithms.map { Int($0.rawValue) })
                    guard token == generation, cloudPasskeyService.sessionGeneration == vaultGeneration, cloudPasskeyService.isAuthenticated, !Task.isCancelled else { return }
                    let savedCatalog = try await cloudPasskeyService.execute(.catalog, vault: vault, offline: false).requireCatalog()
                    try await AutoFillPublisher.shared.publish(catalog: savedCatalog, vaultID: vault)
                    guard token == generation, cloudPasskeyService.sessionGeneration == vaultGeneration, cloudPasskeyService.isAuthenticated, !Task.isCancelled else { return }
                    extensionContext.completeRegistrationRequest(using: ASPasskeyRegistrationCredential(relyingParty: rp, clientDataHash: request.clientDataHash, credentialID: row.credential.credentialID!, attestationObject: try CloudCredentialService.attestation(row))) { _ in }
                } else {
                    guard let suggestion = model.cloudPasskeys.first(where: { $0.id == selection && AutoFillEntry.vaultID($0.recordIdentifier) == vault }), let hash = parameters?.clientDataHash ?? request?.clientDataHash else { throw MopError.notFound }
                    let allowed = parameters?.allowedCredentials ?? (request.flatMap { $0.credentialIdentity as? ASPasskeyCredentialIdentity }.map { [$0.credentialID] } ?? [])
                    let row = try await provider.resolvePasskey(suggestion, relyingParty: rp, allowed: allowed)
                    guard token == generation, cloudPasskeyService.sessionGeneration == vaultGeneration, cloudPasskeyService.isAuthenticated, !Task.isCancelled else { return }
                    let result = try await provider.assertPasskey(row, relyingParty: rp, allowed: allowed, clientDataHash: hash)
                    guard token == generation, cloudPasskeyService.sessionGeneration == vaultGeneration, cloudPasskeyService.isAuthenticated, !Task.isCancelled else { return }
                    extensionContext.completeAssertionRequest(using: ASPasskeyAssertionCredential(userHandle: row.credential.userHandle!, relyingParty: rp, signature: result.signature, clientDataHash: hash, authenticatorData: result.authenticatorData, credentialID: row.credential.credentialID!), completionHandler: nil)
                }
            } catch {
                guard token == generation else { return }; model.message = error.localizedDescription
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
        preferredContentSize = model.showsPicker ? NSSize(width: 480, height: 640) : NSSize(width: 440, height: model.message == nil ? 300 : 440)
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
        case .notFound: model.message = "This account was changed or removed. Choose another account, or refresh suggestions in 2ndPass."
        case .vaultMissing: model.message = "This suggestion belongs to a vault that is no longer available on this device. Open 2ndPass and refresh suggestions, then choose the account again."
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
        model.loginDraft = nil; model.loginVaults = []; model.loginVault = ""
        passkeyAuthorization?.revoke(); passkeyAuthorization = nil; passkeyRequest = nil; passkeyParameters = nil
        model.passkeyRP = nil; model.passkeys = []; model.cloudPasskeys = []; model.passkeyVaults = []; cloudPasskeyService.lock()
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
        guard session != nil || model.passkeyRP != nil || model.loginDraft != nil else { return }
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
    var loginDraft: AutoFillLoginDraft?
    var loginVaults: [VaultDescriptor] = []
    var loginVault = ""
    var passkeyRP: String?
    var passkeyRegistration = false
    var passkeys: [LocalIdentity] = []
    var cloudPasskeys: [AutoFillIdentity] = []
    var passkeyVaults: [VaultDescriptor] = []
    var showsPicker = false
    var textInsertion = false
    var kind: AutoFillKind? = .password
    var entries: [AutoFillIdentity] = []
    var hosts: Set<String> = []
    var loading = true
    var message: String?
}

private struct CredentialRootView: View {
    @Bindable var model: CredentialListModel
    let saveLogin: () -> Void
    let reloadLoginVaults: () -> Void
    let passkeyPerform: (String?, String) -> Void
    let select: (AutoFillIdentity, CredentialField?) -> Void
    let retry: () -> Void
    let chooseAnother: () -> Void
    let cancel: () -> Void
    let resizePasskey: (CGFloat) -> Void
    var body: some View {
        if model.loginDraft != nil {
            SaveLoginView(model: model, save: saveLogin, reload: reloadLoginVaults, cancel: cancel)
        } else if let rp = model.passkeyRP {
            LocalPasskeyPrompt(relyingParty: rp, registration: model.passkeyRegistration, identities: model.passkeys, cloud: model.cloudPasskeys, vaults: model.passkeyVaults, busy: model.loading, message: model.message, perform: passkeyPerform, cancel: cancel, resize: resizePasskey)
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
    @State private var unrelated: AutoFillIdentity?
    @State private var insertionField: CredentialField?
    @FocusState private var searchFocused: Bool
    private var filtered: [AutoFillIdentity] {
        model.entries.filter { search.isEmpty || [$0.website, $0.username].contains { $0.localizedCaseInsensitiveContains(search) } }
    }
    private var ordered: [AutoFillIdentity] {
        matching + (model.hosts.isEmpty || showsOtherAccounts ? other : [])
    }
    private var matching: [AutoFillIdentity] { filtered.filter { model.hosts.contains($0.website) } }
    private var other: [AutoFillIdentity] { filtered.filter { !model.hosts.contains($0.website) } }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            AutoFillDialogHeader(title: "2ndPass AutoFill", subtitle: model.hosts.isEmpty ? nil : "Filling for " + model.hosts.sorted().joined(separator: ", "))
            if model.loading { ProgressView(model.showsPicker && model.entries.isEmpty ? "Loading accounts…" : "Authenticating for AutoFill…") }
            if let message = model.message {
                Text(message).font(.callout).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Retry", action: retry).disabled(model.loading)
                    Button("Choose Another Account", action: chooseAnother).disabled(model.loading)
                }
            }
            if model.showsPicker && !model.entries.isEmpty {
                TextField("Search usernames or websites", text: $search).textFieldStyle(.roundedBorder).focused($searchFocused)
                    .onSubmit { fillSelected() }
                    .onKeyPress(.downArrow) { moveSelection(1); return .handled }
                    .onKeyPress(.upArrow) { moveSelection(-1); return .handled }
                if !model.hosts.isEmpty {
                    if !model.entries.contains(where: { model.hosts.contains($0.website) }) {
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
            Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
        }.padding(24).frame(minWidth: 280, minHeight: model.showsPicker ? 300 : 120)
        .frame(maxHeight: .infinity, alignment: .top)
        .onChange(of: model.entries) { _, _ in
            selection = ordered.first?.id; searchFocused = !model.entries.isEmpty
            if model.entries.isEmpty { unrelated = nil; search = ""; showsOtherAccounts = false }
        }
        .onChange(of: model.hosts) { _, _ in
            showsOtherAccounts = false; unrelated = nil; selection = ordered.first?.id
        }
        .onChange(of: search) { _, _ in selection = ordered.first?.id }
        .sheet(item: $unrelated) { account in
            VStack(spacing: 24) {
                AutoFillDialogHeader(title: "Use this account for another website?")
                Text("The requested site is \(model.hosts.sorted().joined(separator: ", ")). This account is for \(account.website): \(account.username).")
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Cancel", role: .cancel) { unrelated = nil }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Fill Account") { unrelated = nil; select(account, insertionField) }
                        .buttonStyle(.borderedProminent).disabled(model.loading)
                }
            }.padding(24)
                #if os(macOS)
                .frame(width: 432)
                #else
                .frame(maxHeight: .infinity, alignment: .top)
                #endif
                .presentationDetents([.medium, .large])
        }
    }
    @ViewBuilder private func section(_ title: String, entries: [AutoFillIdentity]) -> some View {
        if !entries.isEmpty {
            Section(title) {
                ForEach(entries) { entry in
                    VStack(alignment: .leading, spacing: 5) {
                        Text(entry.username).font(.headline)
                        Text(entry.website).foregroundStyle(.secondary)
                        if model.textInsertion {
                            HStack {
                                if entry.kind == .oneTimeCode { Button("Code") { choose(entry, field: .code) } }
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
    private func choose(_ entry: AutoFillIdentity, field: CredentialField? = nil) {
        guard !model.loading else { return }
        if !model.hosts.isEmpty && !model.hosts.contains(entry.website) { insertionField = field; unrelated = entry }
        else { select(entry, field) }
    }
    private func fillSelected() {
        guard let entry = ordered.first(where: { $0.id == selection }) else { return }
        choose(entry, field: model.textInsertion ? (entry.kind == .oneTimeCode ? .code : .password) : nil)
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

private struct SaveLoginView: View {
    @Bindable var model: CredentialListModel
    let save: () -> Void
    let reload: () -> Void
    let cancel: () -> Void
    private func field(_ key: WritableKeyPath<AutoFillLoginDraft, String>) -> Binding<String> {
        Binding(get: { model.loginDraft?[keyPath: key] ?? "" }, set: { model.loginDraft?[keyPath: key] = $0 })
    }
    var body: some View {
        VStack(spacing: 0) {
            AutoFillDialogHeader(title: "Save Login", subtitle: model.loginDraft?.website ?? "")
                .padding()
            Form {
                Section {
                    TextField("Name", text: field(\.name))
                        .accessibilityIdentifier("save-login-name")
                    TextField("Username", text: field(\.username))
                        .autocorrectionDisabled()
                    SecureField("Password", text: field(\.password))
                    Picker("Save in", selection: $model.loginVault) {
                        Text("Choose a vault…").tag("")
                        ForEach(model.loginVaults, id: \.id) { vault in Text(vault.name ?? vault.id).tag(vault.id) }
                    }.accessibilityIdentifier("save-login-vault")
                } footer: {
                    Text("Saved as a new login in the selected vault. Members of a shared vault will also have access.")
                }
                if let message = model.message {
                    Section {
                        Text(message).foregroundStyle(.secondary)
                        Button("Reload Vaults", action: reload)
                    }
                }
            }.formStyle(.grouped).disabled(model.loading)
            Divider()
            HStack {
                Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                Spacer()
                if model.loading { ProgressView().controlSize(.small).accessibilityLabel("Saving or loading vaults") }
                Button("Save Login", action: save).buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.loading || model.loginDraft?.canSave != true || model.loginVault.isEmpty)
            }.padding()
        }
    }
}
