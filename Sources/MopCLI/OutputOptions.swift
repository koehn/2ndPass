import ArgumentParser
import Foundation
import MopCore

struct OutputOptions: ParsableArguments {
    @Option(name: [.short, .long], help: "Write atomically to a regular file instead of stdout.", completion: .file()) var outFile: String?
    @Option(help: "Octal output permissions (default: 0600); requires --out-file.") var fileMode: String?
    @Flag(name: [.short, .long], help: "Replace an existing output file; requires --out-file.") var force = false

    func destination(storage: VaultOptions) throws -> OutputFile? {
        let mode = try OutputFile.permissions(fileMode)
        guard let outFile else {
            guard fileMode == nil && !force else { throw MopError.invalidOutput }
            return nil
        }
        return try OutputFile(url: URL(fileURLWithPath: outFile), force: force, mode: mode,
                              protectedFiles: [storage.fileURL, storage.stateURL.appendingPathComponent("device.json")],
                              protectedDirectories: [URL(fileURLWithPath: storage.fileURL.path + ".history"), storage.stateURL.appendingPathComponent("trust")])
    }

    func emit(_ text: String, to destination: OutputFile?) throws {
        if let destination { try destination.write(Data(text.utf8)) }
        else { try IO.output(text) }
    }
}
