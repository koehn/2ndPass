// Disposable hardware experiment; does not access Mop identities or vaults.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
enum SessionError: Error { case locked }
let binding = Data("mop.wrapped-session.prototype.v1".utf8)

struct Envelope {
    let encapsulated: Data
    let ciphertext: Data
    init(_ bytes: Data, to key: P256.KeyAgreement.PublicKey) throws {
        var sender = try HPKE.Sender(recipientKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: binding)
        ciphertext = try sender.seal(bytes)
        encapsulated = sender.encapsulatedKey
    }
    func open<K: HPKEDiffieHellmanPrivateKey>(_ key: K) throws -> Data {
        var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256,
                                          info: binding, encapsulatedKey: encapsulated)
        return try recipient.open(ciphertext)
    }
}
struct Record {
    let wrappedContentKey: Envelope
    let ciphertext: Data
    let signature: Data
}

// No key handles escape this owner. close() waits for admitted operations and
// prevents later operations, including work queued before close, from using keys.
final class Session: @unchecked Sendable {
    private let gate = NSLock()
    private var encryption: P256.KeyAgreement.PrivateKey?
    private var signing: P256.Signing.PrivateKey?
    init(bundle: Data) throws {
        guard bundle.count == 64 else { throw Failure("Invalid key bundle") }
        encryption = try P256.KeyAgreement.PrivateKey(rawRepresentation: bundle.prefix(32))
        signing = try P256.Signing.PrivateKey(rawRepresentation: bundle.suffix(32))
    }
    func write(_ plaintext: Data) throws -> Record {
        gate.lock(); defer { gate.unlock() }
        guard let encryption, let signing else { throw SessionError.locked }
        let key = SymmetricKey(size: .bits256)
        var bytes = key.withUnsafeBytes { Data($0) }
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        let wrapped = try Envelope(bytes, to: encryption.publicKey)
        let ciphertext = try AES.GCM.seal(plaintext, using: key, authenticating: binding).combined!
        let signature = try signing.signature(for: wrapped.encapsulated + wrapped.ciphertext + ciphertext).rawRepresentation
        return Record(wrappedContentKey: wrapped, ciphertext: ciphertext, signature: signature)
    }
    func read(_ record: Record) throws -> Data {
        gate.lock(); defer { gate.unlock() }
        guard let encryption, let signing else { throw SessionError.locked }
        let signed = record.wrappedContentKey.encapsulated + record.wrappedContentKey.ciphertext + record.ciphertext
        guard try signing.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: record.signature), for: signed) else {
            throw Failure("Invalid record signature")
        }
        var bytes = try record.wrappedContentKey.open(encryption)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: record.ciphertext), using: SymmetricKey(data: bytes), authenticating: binding)
    }
    func close() {
        gate.lock(); defer { gate.unlock() }
        encryption = nil; signing = nil
    }
    deinit { close() }
}

func makeBundle() -> Data {
    P256.KeyAgreement.PrivateKey().rawRepresentation + P256.Signing.PrivateKey().rawRepresentation
}
func require(_ value: Bool, _ message: String) throws {
    guard value else { throw Failure(message) }
}
func roundTrip(_ session: Session, _ label: String) throws -> Record {
    let plaintext = Data("Disposable test secret: \(label)".utf8)
    let record = try session.write(plaintext)
    try require(try session.read(record) == plaintext, "Round trip failed: \(label)")
    print("PASS: signed write and decrypted read — \(label)")
    return record
}
func requiresLocked(_ operation: () throws -> Void) throws {
    do { try operation() } catch SessionError.locked { return }
    throw Failure("Closed session accepted an operation")
}
func checkLock(_ session: Session, _ record: Record) throws {
    // A worker holds the old provider before lock, but is admitted afterward.
    let ready = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
    final class Outcome: @unchecked Sendable { var error: Error? }
    let outcome = Outcome()
    DispatchQueue.global().async {
        ready.signal(); resume.wait()
        do {
            try requiresLocked { _ = try session.read(record) }
            try requiresLocked { _ = try session.write(Data()) }
        } catch { outcome.error = error }
        done.signal()
    }
    ready.wait(); session.close(); resume.signal(); done.wait()
    if let error = outcome.error { throw error }
    try requiresLocked { _ = try session.read(record) }
    try requiresLocked { _ = try session.write(Data()) }
    print("PASS: lock rejects reads, writes, and delayed work holding the old session")
}
func authenticate(_ reason: String) throws -> LAContext {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedReason = reason
    let done = DispatchSemaphore(value: 0)
    final class Outcome: @unchecked Sendable { var success = false; var error: Error? }
    let outcome = Outcome()
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
        outcome.success = success; outcome.error = error; done.signal()
    }
    done.wait()
    guard outcome.success else { context.invalidate(); throw outcome.error ?? Failure("Authentication failed") }
    context.interactionNotAllowed = true
    return context
}
func interactionRequired(_ error: Error) -> Bool {
    let e = error as NSError
    if e.domain == LAError.errorDomain && e.code == LAError.notInteractive.rawValue { return true }
    if e.domain == "com.apple.LocalAuthentication" && e.code == -1004 { return true }
    if e.domain == NSOSStatusErrorDomain && e.code == Int(errSecInteractionNotAllowed) { return true }
    if let underlying = e.userInfo[NSUnderlyingErrorKey] as? Error { return interactionRequired(underlying) }
    return false
}
func unlock(_ wrapped: Envelope, representation: Data, context: LAContext) throws -> Session {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: representation, authenticationContext: context)
    var bundle = try wrapped.open(key)
    defer { bundle.resetBytes(in: 0..<bundle.count) }
    return try Session(bundle: bundle)
}
func checkNoAuthentication(_ wrapped: Envelope, _ representation: Data) throws {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.interactionNotAllowed = true
    defer { context.invalidate() }
    do {
        let unexpected = try unlock(wrapped, representation: representation, context: context)
        unexpected.close()
    } catch {
        guard interactionRequired(error) else { throw error }
        print("PASS: fresh noninteractive context cannot unlock (\((error as NSError).domain):\((error as NSError).code))")
        return
    }
    throw Failure("Unlock succeeded without fresh authentication")
}

func run() throws -> Int32 {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--self-test"] {
        var bundle = makeBundle(); defer { bundle.resetBytes(in: 0..<bundle.count) }
        let session = try Session(bundle: bundle)
        let record = try roundTrip(session, "software lifecycle")
        let corrupt = Record(wrappedContentKey: record.wrappedContentKey, ciphertext: record.ciphertext + Data([0]), signature: record.signature)
        do { _ = try session.read(corrupt); throw Failure("Tampering accepted") }
        catch let e as Failure where e.description == "Invalid record signature" { print("PASS: tampered record rejected") }
        try checkLock(session, record)
        let reopened = try Session(bundle: bundle); defer { reopened.close() }
        try require(try reopened.read(record) == Data("Disposable test secret: software lifecycle".utf8), "Reopened read failed")
        print("PASS: reopened session reads prior record; NO hardware claims")
        return 0
    }
    guard args.first == "--run", args.count == 1 || (args.count == 3 && args[1] == "--wait-seconds"),
          let wait = args.count == 1 ? 660.0 : Double(args[2]), wait.isFinite, wait >= 1 else {
        print("Usage: wrapped-session --self-test | --run [--wait-seconds 660]\nHardware run prompts twice. Keep Mac awake and unlocked. No production data accessed.")
        return 64
    }
    guard SecureEnclave.isAvailable else { throw Failure("Secure Enclave unavailable; no software fallback") }
    print("Hardware run: \(ProcessInfo.processInfo.operatingSystemVersionString); wait \(wait)s")
    let first = try authenticate("unlock disposable wrapped-key prototype (first unlock)")
    defer { first.invalidate() }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .userPresence], &error) else {
        throw Failure("Cannot create enclave access control")
    }
    let representation: Data
    let wrapped: Envelope
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: first)
        representation = key.dataRepresentation
        var bundle = makeBundle(); defer { bundle.resetBytes(in: 0..<bundle.count) }
        wrapped = try Envelope(bundle, to: key.publicKey)
    }
    let session = try unlock(wrapped, representation: representation, context: first)
    defer { session.close() }
    let original = try roundTrip(session, "initial unlock")
    try checkNoAuthentication(wrapped, representation)
    print("Waiting without enclave operations. Authentication-expiry result requires an actual interaction-required failure.")
    let start = ProcessInfo.processInfo.systemUptime
    while ProcessInfo.processInfo.systemUptime - start < wait {
        Thread.sleep(forTimeInterval: min(30, wait - (ProcessInfo.processInfo.systemUptime - start)))
        print("WAIT: \(Int(ProcessInfo.processInfo.systemUptime - start))s elapsed")
    }
    var expired = false
    do {
        let control = try unlock(wrapped, representation: representation, context: first)
        control.close()
        print("INCONCLUSIVE: original authentication still permits enclave unwrap; natural expiry not observed")
    } catch {
        guard interactionRequired(error) else { throw error }
        expired = true
        print("PASS: original context now requires interaction (\((error as NSError).domain):\((error as NSError).code))")
    }
    _ = try roundTrip(session, expired ? "after observed authentication expiry" : "after wait (expiry unproven)")
    try require(try session.read(original) == Data("Disposable test secret: initial unlock".utf8), "Prior record read failed")
    first.invalidate()
    _ = try roundTrip(session, "after explicit LAContext invalidation")
    try checkLock(session, original)
    try checkNoAuthentication(wrapped, representation)
    print("Authenticate again in the system prompt to complete re-unlock verification.")
    let second = try authenticate("unlock disposable wrapped-key prototype again after lock")
    defer { second.invalidate() }
    let reopened = try unlock(wrapped, representation: representation, context: second)
    defer { reopened.close() }
    try require(try reopened.read(original) == Data("Disposable test secret: initial unlock".utf8), "Re-unlock read failed")
    _ = try roundTrip(reopened, "fresh authenticated re-unlock")
    try requiresLocked { _ = try session.read(original) }
    print("PASS: re-unlock does not revive old session")
    print(expired ? "PASS: all hardware checks" : "INCONCLUSIVE: lifecycle passed, but natural authentication expiry was not observed; retry with a longer wait")
    return expired ? 0 : 2
}
setbuf(stdout, nil)
do { exit(try run()) }
catch {
    let e = error as NSError
    print("FAIL: \(error) [\(e.domain):\(e.code)]")
    exit(1)
}
