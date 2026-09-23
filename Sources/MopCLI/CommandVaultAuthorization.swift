import MopCore
import MopVault

/// Lazily authorizes once for a command; individual vault stores borrow the opener.
final class CommandVaultAuthorization {
    typealias Device = (opener: any VaultKeyOpener, close: () -> Void)
    private let open: () throws -> Device
    private var device: Device?
    private var closed = false

    init(open: @escaping () throws -> Device) { self.open = open }

    func opener() throws -> any VaultKeyOpener {
        guard !closed else { throw MopError.authentication }
        if let device { return device.opener }
        let device = try open()
        self.device = device
        return device.opener
    }

    func close() {
        guard !closed else { return }
        closed = true
        device?.close()
        device = nil
    }
    deinit { close() }
}
