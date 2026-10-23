import Foundation
import MopCore
import MopSync
import MopVaultNext

extension GrantBackedContentSession {
    /// Re-sign only an uncommitted access proposal after an independently pinned
    /// competing head. Content and its pending edits are never rewritten here.
    func reconcileMembership(_ operation: SyncOperation, scope: EnrollmentScope,
                             owner: any RepositoryWritePermit) async throws -> Bool {
        let approval = try? DeviceEnrollmentApproval.decode(operation.payload)
        let commit = approval == nil ? try JSONDecoder().decode(ContentMembershipCommit.self, from: operation.payload) : nil
        let proposed = try approval?.verifiedHistory() ?? commit!.verified()
        guard let parent = proposed.orderedStates.dropLast().last else { throw MopError.vaultUntrusted }
        if (try? history.state(forDigest: proposed.current.digest())) != nil || parent == history.current { return false }
        // The proposal's parent must be an ancestor of our trusted head. A fork
        // in already committed history remains a trust failure, not a rebase.
        guard try history.state(forDigest: parent.digest()) == parent else { throw MopError.vaultUntrusted }
        let authorization = ContentWorkPermit(owner: owner, session: permit)
        if let approval {
            guard approval.request.scope == scope else { throw MopError.vaultUntrusted }
            if approval.request.expiresAt <= Date() {
                try await repository.rebaseUncommittedMembership(operation, payload: nil, approval: nil, permit: authorization)
                return true
            }
            let next = try permit.withDevice { device in
                if history.current.membership.devices.contains(approval.request.identity) {
                    return try DeviceEnrollmentApproval.reconnect(request: approval.request, history: history, owner: device, expectedItemCount: approval.expectedItemCount)
                }
                return try DeviceEnrollmentApproval.create(request: approval.request, history: history, owner: device, expectedItemCount: approval.expectedItemCount)
            }
            let wrapper = try permit.withDevice { try CoordinationEnvelope.sign(kind: .enrollmentApproval, scope: scope,
                identity: next.request.id, payload: next.encoded(), history: history, device: $0) }
            let record = try PreparedCoordinationRecord(account: binding.account, vault: binding.vaultID, kind: .enrollmentApproval,
                identity: next.request.id, bytes: wrapper.encoded())
            try await repository.rebaseUncommittedMembership(operation, payload: next.isReconnect ? nil : next.encoded(), approval: record, permit: authorization)
        } else {
            let current = history.current.membership, previous = parent.membership, desired = proposed.current.membership
            let removed = Set(previous.devices.map(\.device)).subtracting(desired.devices.map(\.device))
            let added = desired.devices.filter { candidate in !previous.devices.contains(where: { $0.device == candidate.device }) }
            guard added.allSatisfy({ candidate in
                !(current.removedDevices ?? []).contains(candidate.device)
                    && !current.devices.contains(where: { $0.device == candidate.device && $0 != candidate })
                    && current.accounts.contains(where: { $0.id == candidate.member })
            }) else { throw MopError.vaultUntrusted }
            let accounts = current.accounts.map { account in
                AccountMember(id: account.id, role: account.role,
                    devices: account.devices.filter { !removed.contains($0.device) }
                        + added.filter { $0.member == account.id && !account.devices.contains($0) })
            }
            let target = try Membership(accounts: accounts,
                offlineRecovery: previous.offlineRecovery == desired.offlineRecovery ? current.offlineRecovery : desired.offlineRecovery,
                removedDevices: removed.isEmpty ? current.removedDevices : Array(Set(current.removedDevices ?? []).union(removed)).sorted { $0.uuidString < $1.uuidString })
            if target == current {
                try await repository.rebaseUncommittedMembership(operation, payload: nil, approval: nil, permit: authorization)
                return true
            }
            let successor = try permit.withDevice { try MembershipEnvelope.successor(of: history.current, membership: target, owner: $0) }
            try await repository.rebaseUncommittedMembership(operation,
                payload: setupEncode(ContentMembershipCommit(history: history.orderedStates, successor: successor)), approval: nil, permit: authorization)
        }
        return true
    }
}
