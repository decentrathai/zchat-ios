// PAR-0003 (iOS app shell T0-pre): the app entry point. One window, the diagnostics screen; no network, no storage.
import SwiftUI

@main
struct ZChatApp: App {
    var body: some Scene {
        WindowGroup {
            DiagnosticsView()
        }
    }
}
