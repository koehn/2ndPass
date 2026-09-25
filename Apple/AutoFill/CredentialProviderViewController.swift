import AuthenticationServices
import CloudKit
import OSLog
import SwiftUI
import MopAppSupport
import MopCore

@MainActor final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var service: NativeVaultService?
    private var task: Task<Void, Never>?
    private var accountObserver: AccountObservation?
    private var pendingIdentity: ASPasswordCredentialIdentity?
    private let model = CredentialListModel()

    override func loadView() {
        let content = CredentialListView(model: model, select: { [weak self] in self?.fill($0, field: $1) }, cancel: { [weak self] in self?.cancel() })
        #if os(macOS)
        let host = NSHostingController(rootView: content)
        addChild(host)
        view = host.view
        #else
        let host = UIHostingController(rootView: content)
        // Keep the hosting view inside a separate container so UIKit can manage
        // the extension's presentation and the child's layout independently.
        view = UIView()
        view.backgroundColor = .systemBackground
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        host.didMove(toParent: self)
        #endif
        observeAccountChanges()
        #if os(macOS)
        updatePreferredContentSize()
        #endif
    }

    private func observeAccountChanges() {
        guard accountObserver == nil else { return }
        accountObserver = AccountObservation(NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in
                self?.cancel()
                await AutoFillStorage.invalidate()
            }
        })
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        stop()
        pendingIdentity = nil
        model.showsPicker = true
        model.textInsertion = false
        updatePreferredContentSize()
        model.loading = true
        model.message = nil
        task = Task {
            let identities: [ASPasswordCredentialIdentity]
            do {
                let directory = try AutoFillStorage.directory()
                let entries = try await Task.detached { try AutoFillIndex(directory: directory).load() }.value
                identities = entries.map(\.identity)
            } catch {
                guard !Task.isCancelled else { return }
                Logger(subsystem: "com.koehn.mop", category: "AutoFill").error("Unable to read the shared credential index.")
                model.entries = []
                model.message = "Mop couldn’t read its AutoFill list. Open and unlock Mop to refresh it, then try again."
                model.loading = false
                return
            }
            guard !Task.isCancelled else { return }
            let hosts = Set(serviceIdentifiers.compactMap { AutoFillEntry.website($0.identifier) })
            model.entries = identities.sorted {
                let left = hosts.contains($0.serviceIdentifier.identifier), right = hosts.contains($1.serviceIdentifier.identifier)
                if left != right { return left }
                return ($0.serviceIdentifier.identifier, $0.user) < ($1.serviceIdentifier.identifier, $1.user)
            }
            model.loading = false
        }
    }
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        // A website may have an active passkey request while the user chooses
        // Passwords. Mop still offers its passwords through this entry point.
        prepareCredentialList(for: serviceIdentifiers)
    }
    #if os(iOS)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        prepareCredentialList(for: [])
        model.textInsertion = true
    }
    #endif
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        guard let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity else { cancel(); return }
        provideCredentialWithoutUserInteraction(for: identity)
    }
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        stop()
        pendingIdentity = nil
        observeAccountChanges()
        guard let identifier = credentialIdentity.recordIdentifier else {
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.credentialIdentityNotFound.rawValue))
            return
        }
        task = Task {
            do {
                try await AutoFillAccess.completeSystemRequest(recordIdentifier: identifier, context: extensionContext)
            } catch {
                guard !Task.isCancelled else { return }
                let code: ASExtensionError.Code
                switch error as? MopError {
                case .authentication: code = .userInteractionRequired
                case .notFound, .vaultMissing: code = .credentialIdentityNotFound
                default: code = .failed
                }
                extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
            }
        }
    }
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        guard let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity else { cancel(); return }
        prepareInterfaceToProvideCredential(for: identity)
    }
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        stop()
        pendingIdentity = nil
        model.showsPicker = false
        model.textInsertion = false
        model.entries = []
        updatePreferredContentSize()
        model.message = nil
        model.loading = true
        if isViewLoaded, view.window != nil { fill(credentialIdentity) }
        else { pendingIdentity = credentialIdentity }
    }
    #if os(macOS)
    override func viewDidAppear() {
        super.viewDidAppear()
        if let identity = pendingIdentity { pendingIdentity = nil; fill(identity) }
    }
    override func viewDidDisappear() { super.viewDidDisappear(); stop() }
    #else
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if let identity = pendingIdentity { pendingIdentity = nil; fill(identity) }
    }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        // A system authentication presentation may temporarily cover the picker.
        // Only cancel for dismissal/removal, not every visibility transition.
        if isBeingDismissed || isMovingFromParent { stop() }
    }
    #endif

    private func updatePreferredContentSize() {
        #if os(macOS)
        preferredContentSize = model.showsPicker
            ? NSSize(width: 420, height: 480)
            : NSSize(width: 360, height: 140)
        #endif
    }

    private func fill(_ identity: ASPasswordCredentialIdentity, field: CredentialField? = nil) {
        guard let identifier = identity.recordIdentifier else { cancel(); return }
        stop()
        model.message = nil
        model.loading = true
        task = Task {
            do {
                let service = NativeVaultService(state: try AutoFillStorage.directory())
                self.service = service
                let credential = try await AutoFillAccess.credential(recordIdentifier: identifier, service: service)
                try Task.checkCancellation()
                service.lock(); self.service = nil
                let completed: @Sendable (Bool) -> Void = { expired in
                    Logger(subsystem: "com.koehn.mop", category: "AutoFill").notice("Interactive request completion callback; expired=\(expired)")
                }
                #if os(iOS)
                if let field {
                    let text = field == .username ? credential.user : credential.password
                    Logger(subsystem: "com.koehn.mop", category: "AutoFill").notice("Returning authenticated text.")
                    extensionContext.completeRequest(withTextToInsert: text, completionHandler: completed)
                    return
                }
                #endif
                Logger(subsystem: "com.koehn.mop", category: "AutoFill").notice("Returning authenticated credential.")
                extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: completed)
            } catch {
                guard !Task.isCancelled else { return }
                service?.lock(); service = nil
                if !model.showsPicker, (error as? MopError) == .authentication {
                    cancel()
                    return
                }
                model.loading = false
                model.message = (error as? MopError) == .authentication
                    ? "Authentication was cancelled. Select an account to try again."
                    : "This credential is unavailable. Open and unlock Mop to refresh AutoFill."
                if model.showsPicker, model.entries.isEmpty { model.entries = [identity] }
            }
        }
    }
    private func stop() {
        let wasLoading = task != nil && model.loading
        task?.cancel(); task = nil; service?.lock(); service = nil
        model.loading = false
        if wasLoading { model.message = "The request was interrupted. Select an account to try again." }
    }
    private func cancel() {
        stop()
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }
}

private enum CredentialField { case username, password }

@MainActor @Observable private final class CredentialListModel {
    // Start without a picker so a selected-credential request cannot flash the list
    // while AuthenticationServices is loading the view.
    var showsPicker = false
    var textInsertion = false
    var entries: [ASPasswordCredentialIdentity] = []
    var loading = true
    var message: String?
}

private struct CredentialListView: View {
    @Bindable var model: CredentialListModel
    let select: (ASPasswordCredentialIdentity, CredentialField?) -> Void
    let cancel: () -> Void
    @State private var search = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Text("Mop AutoFill").font(.headline); Spacer(); Button("Cancel", action: cancel) }
            if model.loading { ProgressView(model.showsPicker ? "Please wait…" : "Unlocking to fill your login…") }
            if let message = model.message { Text(message).font(.callout) }
            if model.showsPicker {
                if model.textInsertion { Text("Choose the username or password to insert into the selected field.").font(.callout) }
                if !model.loading && model.entries.isEmpty && model.message == nil {
                    Text("No logins are available in this AutoFill list. Open and unlock Mop to refresh it, then try again.")
                }
                TextField("Search websites or usernames", text: $search)
                    .textFieldStyle(.roundedBorder)
                List {
                    ForEach(model.entries.filter { search.isEmpty || $0.user.localizedCaseInsensitiveContains(search) || $0.serviceIdentifier.identifier.localizedCaseInsensitiveContains(search) }, id: \.recordIdentifier) { entry in
                        if model.textInsertion {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(entry.serviceIdentifier.identifier).font(.headline)
                                Text(entry.user).font(.subheadline)
                                HStack {
                                    Button("Username") { select(entry, .username) }
                                    Button("Password") { select(entry, .password) }
                                }.buttonStyle(.bordered).disabled(model.loading)
                            }
                        } else {
                            Button { select(entry, nil) } label: {
                                VStack(alignment: .leading) {
                                    Text(entry.serviceIdentifier.identifier).font(.headline)
                                    Text(entry.user).font(.subheadline)
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }.buttonStyle(.plain).disabled(model.loading)
                        }
                    }
                }
            }
        }.padding().frame(minWidth: 280, minHeight: model.showsPicker ? 300 : 80)
    }
}

// The token is immutable and NotificationCenter supports removal on any thread.
private final class AccountObservation: @unchecked Sendable {
    let token: NSObjectProtocol
    init(_ token: NSObjectProtocol) { self.token = token }
    deinit { NotificationCenter.default.removeObserver(token) }
}
