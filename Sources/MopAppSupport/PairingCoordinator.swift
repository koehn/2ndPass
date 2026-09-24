import Foundation
import Observation
import MopCore
import MopVault

public enum PairingOperation: Sendable {
    case start
    case join(qr: String, name: String, strict: Bool)
    case poll(UUID), approve(UUID), cancel(UUID)
}
public struct PairingProgress: Sendable {
    public enum Phase: Sendable { case displaying, comparing, waiting, awaitingTrust, complete }
    public let session: UUID
    public let vault: UUID
    public let expires: Date
    public let phase: Phase
    public let qr: String?
    public let code: String?
    public let deviceName: String?
    public init(session: UUID, vault: UUID, expires: Date, phase: Phase, qr: String? = nil, code: String? = nil, deviceName: String? = nil) {
        self.session = session; self.vault = vault; self.expires = expires; self.phase = phase
        self.qr = qr; self.code = code; self.deviceName = deviceName
    }
}

/// Owns foreground polling and cancellation; views only render state and send actions.
@MainActor @Observable public final class PairingCoordinator {
    public private(set) var progress: PairingProgress?
    public private(set) var error: String?
    public private(set) var busy = false
    public private(set) var submitted = false
    public private(set) var scanned = false
    public private(set) var finished = false
    private let service: any VaultService
    private let now: () -> Date
    private var scannedQR: String?
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var expiryTask: Task<Void, Never>?
    private var generation = 0
    public init(service: any VaultService, now: @escaping () -> Date = Date.init) { self.service = service; self.now = now }
    public func scan(_ qr: String) {
        guard !scanned, !busy, !finished else { return }
        do {
            let invitation = try PairingInvitation.parse(qr, now: now())
            scannedQR = qr; scanned = true; error = nil
            armExpiry(Date(timeIntervalSince1970: Double(invitation.expires)))
        } catch { self.error = Self.message(error) }
    }
    public func start(vault: String) { run(.start, vault: vault) }
    public func join(name: String, strict: Bool) {
        guard let scannedQR else { return }
        run(.join(qr: scannedQR, name: name, strict: strict), vault: nil)
    }
    public func approve() {
        guard let progress, progress.phase == .comparing else { return }
        submitted = true
        run(.approve(progress.session), vault: progress.vault.uuidString)
    }
    private func armExpiry(_ expires: Date) {
        expiryTask?.cancel()
        expiryTask = Task { [weak self] in
            guard let self else { return }
            do { try await Task.sleep(for: .seconds(max(0, expires.timeIntervalSince(self.now())))) }
            catch { return }
            self.cancel()
            self.error = PairingError.expired.localizedDescription
        }
    }
    private func run(_ operation: PairingOperation, vault: String?) {
        guard !busy, !finished else { return }
        task?.cancel(); generation += 1; let token = generation
        busy = true; error = nil
        task = Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await service.execute(.pairing(operation), vault: vault, offline: false)
                guard token == generation, !Task.isCancelled else { return }
                guard let update = result.pairing else { throw PairingError.invalid }
                accept(update)
                busy = false
                await poll(token: token)
            } catch {
                guard token == generation else { return }
                busy = false; self.error = Self.message(error)
                if progress == nil { cancel(); self.error = Self.message(error) }
            }
        }
    }
    private func accept(_ update: PairingProgress) {
        progress = update
        scannedQR = nil
        armExpiry(update.expires)
        if update.phase == .complete { finished = true; expiryTask?.cancel() }
    }
    private func poll(token: Int) async {
        var delay = 2
        while token == generation, let current = progress,
              current.phase == .displaying || current.phase == .waiting || current.phase == .awaitingTrust {
            do {
                try await Task.sleep(for: .seconds(delay))
                try Task.checkCancellation()
                let result = try await service.execute(.pairing(.poll(current.session)), vault: current.vault.uuidString, offline: false)
                guard token == generation, !Task.isCancelled else { return }
                guard let update = result.pairing else { throw PairingError.invalid }
                accept(update); error = nil; delay = 2
            } catch {
                guard token == generation, !Task.isCancelled else { return }
                if let failure = error as? MopError, [.cloudUnavailable, .cloudThrottled].contains(failure) {
                    self.error = "Waiting for iCloud…"; delay = min(10, delay * 2)
                } else {
                    cancel(); self.error = Self.message(error); return
                }
            }
        }
    }
    private static func message(_ error: Error) -> String {
        (error as? PairingError)?.errorDescription ?? (error as? MopError)?.errorDescription ?? "Pairing could not be completed. Cancel and try again."
    }
    public func cancel() {
        let previous = progress
        generation += 1; task?.cancel(); task = nil; expiryTask?.cancel(); expiryTask = nil
        scannedQR = nil; progress = nil; busy = false; finished = true
        if let previous {
            let service = service
            Task { _ = try? await service.execute(.pairing(.cancel(previous.session)), vault: nil, offline: false) }
        }
    }
    deinit { task?.cancel(); expiryTask?.cancel() }
}
