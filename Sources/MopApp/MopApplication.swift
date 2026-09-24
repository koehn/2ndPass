import SwiftUI
import MopUI

@main
struct MopApplication: App {
    #if os(macOS)
    @NSApplicationDelegateAdaptor(MopApplicationDelegate.self) private var delegate
    #else
    @UIApplicationDelegateAdaptor(MopApplicationDelegate.self) private var delegate
    #endif
    var body: some Scene { MopScenes() }
}
