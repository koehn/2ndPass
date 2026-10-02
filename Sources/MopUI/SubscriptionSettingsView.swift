import SwiftUI
import MopSubscriptions

struct SubscriptionSettingsView: View {
    @State private var subscription = SubscriptionModel.shared
    var body: some View {
        Section("Subscription") {
            Text(subscription.status.diagnostic)
            if let expiration = subscription.status.expiration { LabeledContent("Access through", value: expiration.formatted(date: .abbreviated, time: .shortened)) }
            if let verified = subscription.status.lastVerified { LabeledContent("Last verified", value: verified.formatted(date: .abbreviated, time: .shortened)) }
            Text(subscription.availabilityMessage).font(.callout).foregroundStyle(.secondary)
            if subscription.canPurchase {
                if let price = subscription.price { Button("Subscribe — \(price) / year") { Task { await subscription.purchase() } }.disabled(subscription.busy) }
                Button("Restore Purchases") { Task { await subscription.restore() } }.disabled(subscription.busy)
            }
            Link("Manage Subscription", destination: URL(string: "https://apps.apple.com/account/subscriptions")!)
            Button("Refresh Subscription") { Task { await subscription.refresh() } }.disabled(subscription.busy)
            if !subscription.purchaseMessage.isEmpty { Text(subscription.purchaseMessage).font(.callout) }
            LabeledContent("iCloud", value: subscription.publicationMessage)
        }.task { subscription.start() }
    }
}
