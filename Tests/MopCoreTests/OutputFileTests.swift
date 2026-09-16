import Darwin
import Foundation
import Testing
@testable import MopCore

@Test func atomicOutputPermissionsAndCollisionPolicy() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-output-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("result")
    func writer(force: Bool = false, mode: mode_t = 0o600) throws -> OutputFile {
        try OutputFile(url: file, force: force, mode: mode, protectedFiles: [], protectedDirectories: [])
    }
    let first = try writer()
    #expect(!FileManager.default.fileExists(atPath: file.path))
    try first.write(Data("original".utf8))
    var attributes = stat()
    #expect(stat(file.path, &attributes) == 0)
    #expect(attributes.st_mode & 0o777 == 0o600)
    #expect(throws: MopError.outputExists) { try writer() }
    #expect(throws: MopError.outputExists) { try first.write(Data("unexpected".utf8)) }
    #expect(try Data(contentsOf: file) == Data("original".utf8))
    try writer(force: true, mode: 0o640).write(Data("replacement".utf8))
    #expect(try Data(contentsOf: file) == Data("replacement".utf8))
    #expect(stat(file.path, &attributes) == 0)
    #expect(attributes.st_mode & 0o777 == 0o640)
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["result"])
    for mode in ["888", "1000", "-1", "0x600", "", "00600"] {
        #expect(throws: MopError.invalidOutput) { try OutputFile.permissions(mode) }
    }
    #expect(try OutputFile.permissions(nil) == 0o600)
    #expect(try OutputFile.permissions("0777") == 0o777)
    #expect(try OutputFile.permissions("000") == 0)
}

@Test func rejectsUnsafeAndProtectedOutputDestinations() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("mop-output-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("vault")
    try Data("encrypted".utf8).write(to: file)
    let alias = root.appendingPathComponent("alias")
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: file)
    let hardlink = root.appendingPathComponent("hardlink")
    #expect(link(file.path, hardlink.path) == 0)
    let history = root.appendingPathComponent("vault.history")
    try FileManager.default.createDirectory(at: history, withIntermediateDirectories: true)
    let historyAlias = root.appendingPathComponent("history-alias")
    try FileManager.default.createSymbolicLink(at: historyAlias, withDestinationURL: history)
    for destination in [file, alias, hardlink, root, history.appendingPathComponent("revision"), historyAlias.appendingPathComponent("revision")] {
        #expect(throws: MopError.filePermissions) {
            try OutputFile(url: destination, force: true, mode: 0o600, protectedFiles: [file], protectedDirectories: [history])
        }
    }
    let pending = root.appendingPathComponent("pending")
    let writer = try OutputFile(url: pending, force: true, mode: 0o600, protectedFiles: [file], protectedDirectories: [history])
    try FileManager.default.createSymbolicLink(at: pending, withDestinationURL: file)
    #expect(throws: MopError.filePermissions) { try writer.write(Data("bad".utf8)) }
    #expect(try Data(contentsOf: file) == Data("encrypted".utf8))
}
