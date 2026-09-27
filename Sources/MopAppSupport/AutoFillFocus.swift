/// Tracks the foreground user application for one AutoFill request. Accessory
/// processes (including authentication UI) are not a change of destination app.
public struct AutoFillFocus: Sendable {
    private var host: Int32?
    public init() {}
    public mutating func begin(application: Int32?) { host = application }
    /// Ignore queued notifications that no longer describe the foreground app.
    /// If presentation began with a system panel in front, establish the host
    /// when a regular application next becomes foreground.
    public mutating func shouldInterrupt(activated: Int32?, foreground: Int32?) -> Bool {
        guard let activated, activated == foreground else { return false }
        guard let host else { self.host = activated; return false }
        return activated != host
    }
}
