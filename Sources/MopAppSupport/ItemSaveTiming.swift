import Foundation
import OSLog

/// Save latency diagnostics contain only fixed phase labels and elapsed time.
/// Never pass item names, identifiers, field paths, or values to this logger.
public struct ItemSaveTiming: Sendable {
    private static let logger = Logger(subsystem: "com.koehn.mop", category: "SaveTiming")
    private let started = ContinuousClock.now
    private let trace = UUID().uuidString

    public init() { mark("started") }

    public func mark(_ phase: StaticString) {
        let elapsed = started.duration(to: .now).components
        let milliseconds = Double(elapsed.seconds) * 1_000 + Double(elapsed.attoseconds) / 1e15
        Self.logger.notice("save=\(trace, privacy: .public) phase=\(phase.description, privacy: .public) elapsed_ms=\(milliseconds, privacy: .public)")
    }
}
