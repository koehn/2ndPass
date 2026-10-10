import Foundation
import MopCore

/// A decision about authenticated storage ancestry. This does not acknowledge
/// delivery or mutate receipts: accepting equivalent server content supersedes
/// the local publication instead of claiming that its bytes reached the server.
public enum ContentReconciliation: Equatable, Sendable {
    case acknowledgeDuplicate
    case keepLocal
    case acceptRemote
    case compareContents
    case acceptRemoteSupersedingLocal
    case preserveBranches

    /// Missing ancestry is deliberately conservative. Generation numbers,
    /// timestamps and logical revision IDs are not sufficient proof of ancestry.
    public static func inspect(local: ContentEnvelope, remote: ContentEnvelope,
                               ancestors: [ContentEnvelope], history: TrustedMembershipHistory) throws -> Self {
        let item = local.header.item
        var versions: [UUID: ContentEnvelope] = [:]
        for content in ancestors + [local, remote] {
            try content.verify(history: history, item: item)
            if let existing = versions[content.header.version], existing != content { return .preserveBranches }
            versions[content.header.version] = content
        }
        if local == remote { return .acknowledgeDuplicate }

        func lineage(_ content: ContentEnvelope) -> [UUID]? {
            var cursor = content
            var result = [cursor.header.version]
            while let predecessor = cursor.header.base {
                guard let parent = versions[predecessor] else { break }
                guard parent.header.generation == cursor.header.generation - 1 else { return nil }
                result.append(predecessor)
                cursor = parent
            }
            return result
        }
        // A direct verified edge is sufficient; it need not wait for genesis.
        func descends(_ child: ContentEnvelope, from parent: ContentEnvelope) -> Bool {
            var cursor = child
            while cursor.header.generation > parent.header.generation {
                guard let base = cursor.header.base, let predecessor = versions[base],
                      predecessor.header.generation == cursor.header.generation - 1 else { return false }
                if predecessor == parent { return true }
                cursor = predecessor
            }
            return false
        }
        if descends(local, from: remote) { return .keepLocal }
        if descends(remote, from: local) { return .acceptRemote }
        guard let localLine = lineage(local), let remoteLine = lineage(remote),
              !Set(localLine).isDisjoint(with: remoteLine) else { return .preserveBranches }
        guard local.header.isTombstone == remote.header.isTombstone else { return .preserveBranches }
        return .compareContents
    }

    /// Call only after public inspection requests a content comparison. Both
    /// decryptions use the caller's authorized device; failed verification or a
    /// missing key leaves both branches intact at the repository boundary.
    public static func reconcile(local: ContentEnvelope, remote: ContentEnvelope,
                                 ancestors: [ContentEnvelope], localGrant: ContentKeyGrant,
                                 remoteGrant: ContentKeyGrant, history: TrustedMembershipHistory,
                                 device: any DeviceOperations) throws -> Self {
        let decision = try inspect(local: local, remote: remote, ancestors: ancestors, history: history)
        guard decision == .compareContents else { return decision }
        try remote.verifyForPublication(history: history)
        return try local.hasIdenticalContents(to: remote, grant: localGrant, otherGrant: remoteGrant,
            history: history, device: device) ? .acceptRemoteSupersedingLocal : .preserveBranches
    }
}
