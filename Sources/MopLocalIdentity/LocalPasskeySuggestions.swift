import AuthenticationServices
import Foundation

extension LocalIdentity {
    public var passkeySuggestion: ASPasskeyCredentialIdentity? {
        guard case .passkey(let metadata) = metadata else { return nil }
        return ASPasskeyCredentialIdentity(relyingPartyIdentifier: metadata.relyingParty, userName: metadata.userName, credentialID: metadata.credentialID, userHandle: metadata.userHandle, recordIdentifier: "local/" + id.uuidString)
    }
}
