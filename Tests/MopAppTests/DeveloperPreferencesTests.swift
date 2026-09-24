import Foundation
import Testing
@testable import MopUI

@MainActor struct DeveloperPreferencesTests {
    private func defaults() -> UserDefaults { UserDefaults(suiteName: "mop-preference-test-" + UUID().uuidString)! }
    @Test func changesPropagateWithoutEchoingRemoteWrites() {
        let one = defaults(), two = defaults()
        var cloud: Bool? = true, writes = 0
        let first = DeveloperPreferences(defaults: one, readCloud: { cloud }, writeCloud: { cloud = $0; writes += 1 })
        let second = DeveloperPreferences(defaults: two, readCloud: { cloud }, writeCloud: { cloud = $0; writes += 1 })
        #expect(one.bool(forKey: DeveloperPreferences.key) && two.bool(forKey: DeveloperPreferences.key))
        #expect(writes == 0)
        first.set(false); second.receive()
        #expect(!one.bool(forKey: DeveloperPreferences.key) && !two.bool(forKey: DeveloperPreferences.key))
        #expect(writes == 1)
        second.set(true); first.receive()
        #expect(one.bool(forKey: DeveloperPreferences.key) && two.bool(forKey: DeveloperPreferences.key))
        #expect(writes == 2)
    }
    @Test func initialDownloadWinsOverOldDeviceChoice() {
        let local = defaults()
        local.set(true, forKey: DeveloperPreferences.key)
        var cloud: Bool?, writes = 0
        let preferences = DeveloperPreferences(defaults: local, readCloud: { cloud }, writeCloud: { cloud = $0; writes += 1 })
        #expect(writes == 0)
        cloud = false; preferences.receive(initialSync: true)
        #expect(!local.bool(forKey: DeveloperPreferences.key) && writes == 0)
    }
    @Test func migratesOnlyAfterInitialDownloadAndClearsOnAccountChange() {
        let local = defaults()
        local.set(true, forKey: DeveloperPreferences.key)
        var cloud: Bool?
        let preferences = DeveloperPreferences(defaults: local, readCloud: { cloud }, writeCloud: { cloud = $0 })
        #expect(cloud == nil)
        preferences.receive(initialSync: true)
        #expect(cloud == true)
        cloud = nil; preferences.receive(accountChanged: true)
        #expect(!local.bool(forKey: DeveloperPreferences.key) && cloud == nil)
    }
}
