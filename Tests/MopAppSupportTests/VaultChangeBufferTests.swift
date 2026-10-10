import Foundation
import Testing
@testable import MopAppSupport

@Test func slowVaultObserverRetainsFullInvalidationInsteadOfNotificationBacklog() async {
    let pair = AsyncStream<VaultChange>.makeStream(bufferingPolicy: .bufferingNewest(1))
    for index in 0..<1000 {
        ItemVaultService.emitChange(.display(vault: "vault-\(index)"), to: pair.continuation)
    }
    pair.continuation.finish()
    var count = 0
    for await event in pair.stream {
        count += 1
        guard case .store = event else { Issue.record("Dropped scoped updates require a full refresh"); continue }
    }
    #expect(count == 1)
}

@Test func singleVaultDisplayProgressRemainsScoped() async {
    let pair = AsyncStream<VaultChange>.makeStream(bufferingPolicy: .bufferingNewest(1))
    ItemVaultService.emitChange(.display(vault: "one"), to: pair.continuation)
    pair.continuation.finish()
    for await event in pair.stream {
        guard case .display(let vault) = event else { Issue.record("An isolated display update should stay scoped"); continue }
        #expect(vault == "one")
    }
}
