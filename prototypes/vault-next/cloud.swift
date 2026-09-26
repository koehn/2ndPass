// Standalone signed CloudKit probe. Only touches mop-next-probe-* zones.
// Creates no Mop identity, secret, or recovery material and never deletes a zone.
// Build with swiftc -parse-as-library cloud.swift -o probe, then provision/sign.
@preconcurrency import CloudKit
import Foundation

enum ProbeError: Error { case usage, unsafeZone, missing, unexpectedCAS, invalidShare }

@main struct Probe {
    static let prefix = "mop-next-probe-"
    static func zone(_ name: String, owner: String) throws -> CKRecordZone.ID {
        guard name.hasPrefix(prefix), UUID(uuidString: String(name.dropFirst(prefix.count))) != nil else { throw ProbeError.unsafeZone }
        return CKRecordZone.ID(zoneName: name, ownerName: owner)
    }
    static func clone(_ record: CKRecord) throws -> CKRecord {
        let encoder = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: encoder); encoder.finishEncoding()
        let decoder = try NSKeyedUnarchiver(forReadingFrom: encoder.encodedData)
        decoder.requiresSecureCoding = true
        defer { decoder.finishDecoding() }
        guard let copy = CKRecord(coder: decoder) else { throw ProbeError.missing }
        copy["probe"] = record["probe"]
        return copy
    }
    static func save(_ record: CKRecord, in database: CKDatabase) async throws {
        let result = try await database.modifyRecords(saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
        guard let saved = result.saveResults[record.recordID] else { throw ProbeError.missing }
        _ = try saved.get()
    }
    static func attempt(_ record: CKRecord, in database: CKDatabase) async -> String {
        do { try await save(record, in: database); return "saved" }
        catch let error as CKError where error.code == .serverRecordChanged { return "conflict" }
        catch { return "error:\((error as NSError).domain):\((error as NSError).code)" }
    }
    static func run() async throws {
        let args = Array(CommandLine.arguments.dropFirst())
        guard args.count >= 2 else { throw ProbeError.usage }
        let cloud = CKContainer(identifier: args[0])
        guard try await cloud.accountStatus() == .available else { throw ProbeError.missing }
        let account = try await cloud.userRecordID()
        print("Account record ID: \(account.recordName)")
        switch args[1] {
        case "inspect":
            for database in [cloud.privateCloudDatabase, cloud.sharedCloudDatabase] {
                for zone in try await database.allRecordZones() where zone.zoneID.zoneName.hasPrefix(prefix) {
                    print("Probe zone scope=\(database.databaseScope.rawValue) owner=\(zone.zoneID.ownerName) name=\(zone.zoneID.zoneName)")
                }
            }
        case "create":
            let id = try zone(prefix + UUID().uuidString, owner: CKCurrentUserDefaultName)
            // Print before any mutation, so a dropped response leaves a known locator.
            print("Creating disposable probe zone: \(id.zoneName)")
            _ = try await cloud.privateCloudDatabase.save(CKRecordZone(zoneID: id))
            let head = CKRecord(recordType: "MopNextProbe", recordID: CKRecord.ID(recordName: "head", zoneID: id))
            head["probe"] = "genesis" as CKRecordValue
            try await save(head, in: cloud.privateCloudDatabase)
            print("PASS: zone and initial conditional head created; retained for inspection")
        case "race", "barrier":
            guard args.count == 5, ["private", "shared"].contains(args[2]) else { throw ProbeError.usage }
            let database = args[2] == "private" ? cloud.privateCloudDatabase : cloud.sharedCloudDatabase
            let id = try zone(args[4], owner: args[3])
            let head = try await database.record(for: CKRecord.ID(recordName: "head", zoneID: id))
            if args[1] == "barrier" {
                let barrier = try clone(head), late = try clone(head)
                late["probe"] = UUID().uuidString as CKRecordValue
                try await save(barrier, in: database)
                let fresh = try await database.record(for: head.recordID)
                guard fresh.recordChangeTag != head.recordChangeTag,
                      (fresh["probe"] as? String) == (head["probe"] as? String),
                      await attempt(late, in: database) == "conflict" else { throw ProbeError.unexpectedCAS }
                print("PASS: unchanged-value CAS advances server version and fences a late write using the prior version")
                return
            }
            let first = try clone(head), second = try clone(head)
            let one = UUID().uuidString, two = UUID().uuidString
            first["probe"] = one as CKRecordValue; second["probe"] = two as CKRecordValue
            async let a = attempt(first, in: database)
            async let b = attempt(second, in: database)
            let results = await [a, b]
            guard results.sorted() == ["conflict", "saved"] else {
                print("FAIL: race outcomes \(results)"); throw ProbeError.unexpectedCAS
            }
            let winner = try await database.record(for: head.recordID)
            guard let value = winner["probe"] as? String, [one, two].contains(value) else { throw ProbeError.unexpectedCAS }
            print("PASS: exactly one CAS winner; stale write rejected; server winner verified")
        case "share-info":
            guard args.count == 3 else { throw ProbeError.usage }
            let id = try zone(args[2], owner: CKCurrentUserDefaultName)
            guard let share = try await cloud.privateCloudDatabase.record(for: CKRecord.ID(recordName: CKRecordNameZoneWideShare, zoneID: id)) as? CKShare else { throw ProbeError.invalidShare }
            print("Owner userRecordID: \(share.owner.userIdentity.userRecordID?.recordName ?? "nil")")
            print("Current participant userRecordID: \(share.currentUserParticipant?.userIdentity.userRecordID?.recordName ?? "nil")")
            print("Current participant role: \(share.currentUserParticipant?.role.rawValue ?? -1)")
            print("Participant count: \(share.participants.count), publicPermission none: \(share.publicPermission == .none)")
        case "share", "prepare":
            guard args.count == (args[1] == "share" ? 4 : 3) else { throw ProbeError.usage }
            let id = try zone(args[2], owner: CKCurrentUserDefaultName)
            let share: CKShare
            do {
                guard let existing = try await cloud.privateCloudDatabase.record(for: CKRecord.ID(recordName: CKRecordNameZoneWideShare, zoneID: id)) as? CKShare else { throw ProbeError.invalidShare }
                share = existing
            } catch let error as CKError where error.code == .unknownItem {
                share = CKShare(recordZoneID: id)
            }
            share.publicPermission = .none
            if args[1] == "share" {
                let lookup = CKUserIdentity.LookupInfo(userRecordID: CKRecord.ID(recordName: args[3]))
                let participants = try await cloud.shareParticipants(for: [lookup])
                guard let participantResult = participants[lookup] else { throw ProbeError.missing }
                let participant = try participantResult.get()
                participant.permission = .readWrite
                share.addParticipant(participant)
            }
            let result = try await cloud.privateCloudDatabase.modifyRecords(saving: [share], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
            guard let saved = try result.saveResults[share.recordID]?.get() as? CKShare, let url = saved.url else { throw ProbeError.invalidShare }
            print("Owner participant record matches container userRecordID: \(saved.owner.userIdentity.userRecordID == account)")
            print("publicPermission none: \(saved.publicPermission == .none)")
            print("Prepared private probe share; deliver this URL manually to the intended test account: \(url.absoluteString)")
        case "accept":
            guard args.count == 3, let url = URL(string: args[2]) else { throw ProbeError.usage }
            let metadata = try await cloud.shareMetadata(for: url)
            guard metadata.containerIdentifier == args[0] else { throw ProbeError.invalidShare }
            let id = metadata.share.recordID.zoneID
            _ = try zone(id.zoneName, owner: id.ownerName)
            _ = try await cloud.accept(metadata)
            print("Accepted probe share owner=\(id.ownerName) zone=\(id.zoneName)")
            let head = try await cloud.sharedCloudDatabase.record(for: CKRecord.ID(recordName: "head", zoneID: id))
            guard head.recordType == "MopNextProbe" else { throw ProbeError.invalidShare }
            print("PASS: accepted participant fetched head through shared database with actual ownerName")
        default: throw ProbeError.usage
        }
        print("NOT PROVEN: Mop cryptographic authorization; these records contain only disposable markers")
    }
    static func main() async {
        do { try await run() }
        catch {
            print("BLOCKED/FAIL: \((error as NSError).domain) code \((error as NSError).code)")
            print("Usage: probe CONTAINER inspect | create | race|barrier private|shared OWNER ZONE | prepare|share-info ZONE | share ZONE PARTICIPANT_RECORD_ID | accept URL")
            exit(1)
        }
    }
}
