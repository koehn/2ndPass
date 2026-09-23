import Darwin
import Foundation

/// Immutable, explicitly owned bytes. Sharing retains the same allocation; the last
/// owner wipes its full capacity before freeing it. Never exposes a secret description.
/// Sendable is safe because published storage is immutable and borrows are read-only.
public final class SecretBytes: @unchecked Sendable, ContiguousBytes, RandomAccessCollection,
                                ExpressibleByStringLiteral, Equatable, CustomStringConvertible {
    public typealias Index = Int
    private let storage: UnsafeMutableRawBufferPointer
    public let count: Int
    private let onWipe: (@Sendable (UnsafeRawBufferPointer) -> Void)?
    public var startIndex: Int { 0 }
    public var endIndex: Int { count }
    public var description: String { "<concealed>" }
    public var utf8: SecretBytes { self }
    public subscript(index: Int) -> UInt8 {
        precondition(index >= 0 && index < count)
        return storage[index]
    }
    fileprivate init(storage: UnsafeMutableRawBufferPointer, count: Int, onWipe: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil) {
        self.storage = storage; self.count = count; self.onWipe = onWipe
    }
    public convenience init<C: Collection>(copying bytes: C) where C.Element == UInt8 {
        let storage = UnsafeMutableRawBufferPointer.allocate(byteCount: Swift.max(1, bytes.count), alignment: 1)
        storage.copyBytes(from: bytes)
        self.init(storage: storage, count: bytes.count)
    }
    /// Boundary conversion for UI/OS text only. The source String cannot be wiped.
    public convenience init(utf8 text: String) { self.init(copying: text.utf8) }
    public convenience init(stringLiteral value: String) { self.init(utf8: value) }
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(rebasing: storage[..<count]))
    }
    /// Isolated copy for synchronous APIs requiring Data. Do not retain it beyond
    /// the callback. Framework aliases can survive its best-effort deferred wipe.
    public func withFoundationData<R>(_ body: (Data) throws -> R) rethrows -> R {
        var data = Data(self)
        defer { Self.wipe(&data) }
        return try body(data)
    }
    public static func == (lhs: SecretBytes, rhs: SecretBytes) -> Bool { lhs.elementsEqual(rhs) }
    public static func + (lhs: SecretBytes, rhs: SecretBytes) -> SecretBytes {
        let builder = SecretBuilder(); builder.append(lhs); builder.append(rhs); return builder.finish()
    }
    public func validatedUTF8() throws -> SecretBytes {
        // Validate scalar encodings directly; String validation would create an unwipeable copy.
        var i = 0
        while i < count {
            let first = self[i]; i += 1
            if first < 0x80 { continue }
            let length: Int
            switch first {
            case 0xC2...0xDF: length = 1
            case 0xE0...0xEF: length = 2
            case 0xF0...0xF4: length = 3
            default: throw MopError.invalidUTF8
            }
            guard count - i >= length else { throw MopError.invalidUTF8 }
            for j in 0..<length where !(0x80...0xBF).contains(self[i + j]) { throw MopError.invalidUTF8 }
            guard !(first == 0xE0 && self[i] < 0xA0), !(first == 0xED && self[i] >= 0xA0),
                  !(first == 0xF0 && self[i] < 0x90), !(first == 0xF4 && self[i] >= 0x90) else { throw MopError.invalidUTF8 }
            i += length
        }
        return self
    }
    public static func read(descriptor: Int32) throws -> SecretBytes {
        let builder = SecretBuilder()
        while true {
            let count = try builder.readChunk(descriptor: descriptor)
            if count == 0 { return builder.finish() }
        }
    }
    public func write(descriptor: Int32) throws {
        try withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw MopError.inputOutput }
                offset += written
            }
        }
    }
    /// Framework-owned copies may survive CoW; only our own allocations have an ownership guarantee.
    public static func wipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { bytes in
            if let address = bytes.baseAddress, !bytes.isEmpty {
                let result = memset_s(address, bytes.count, 0, bytes.count)
                precondition(result == 0)
            }
        }
    }
    fileprivate static func destroy(_ storage: UnsafeMutableRawBufferPointer, onWipe: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil) {
        let result = memset_s(storage.baseAddress!, storage.count, 0, storage.count)
        precondition(result == 0)
        onWipe?(UnsafeRawBufferPointer(storage))
        storage.deallocate()
    }
    deinit { Self.destroy(storage, onWipe: onWipe) }
}

/// Single-owner mutable assembly. Growth wipes old storage; finish transfers ownership.
public final class SecretBuilder {
    private var storage = UnsafeMutableRawBufferPointer.allocate(byteCount: 1, alignment: 1)
    public private(set) var count = 0
    private let onWipe: (@Sendable (UnsafeRawBufferPointer) -> Void)?
    public init() { onWipe = nil }
    // Per-instance observer used by tests, called after wiping and before freeing.
    init(onWipe: @escaping @Sendable (UnsafeRawBufferPointer) -> Void) { self.onWipe = onWipe }
    private func reserve(_ required: Int) {
        guard required > storage.count else { return }
        let next = UnsafeMutableRawBufferPointer.allocate(byteCount: Swift.max(required, storage.count * 2), alignment: 1)
        next.copyMemory(from: UnsafeRawBufferPointer(rebasing: storage[..<count]))
        SecretBytes.destroy(storage, onWipe: onWipe); storage = next
    }
    public func append<C: Collection>(_ bytes: C) where C.Element == UInt8 {
        reserve(count + bytes.count)
        UnsafeMutableRawBufferPointer(rebasing: storage[count..<(count + bytes.count)]).copyBytes(from: bytes)
        count += bytes.count
    }
    public func append(_ byte: UInt8) { reserve(count + 1); storage[count] = byte; count += 1 }
    public func readChunk(descriptor: Int32, maximum: Int = 16_384) throws -> Int {
        precondition(maximum > 0)
        reserve(count + maximum)
        var amount: Int
        repeat { amount = Darwin.read(descriptor, storage.baseAddress!.advanced(by: count), maximum) } while amount < 0 && errno == EINTR
        guard amount >= 0 else { throw MopError.inputOutput }
        count += amount
        return amount
    }
    public func finish() -> SecretBytes {
        let result = SecretBytes(storage: storage, count: count, onWipe: onWipe)
        storage = .allocate(byteCount: 1, alignment: 1); count = 0
        return result
    }
    deinit { SecretBytes.destroy(storage, onWipe: onWipe) }
}
