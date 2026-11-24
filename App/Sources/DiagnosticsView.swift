// PAR-0003 (iOS app shell T0-pre): shows ZChatSelfTest.run(). Every rule and expected value lives in ZChatCore;
// this view only displays the results.
import SwiftUI
import ZChatProtocol

struct DiagnosticsView: View {
    private let checks: [SelfTestCheck] = ZChatSelfTest.run()

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("ZChat for iOS — T0-pre diagnostics")
                        .font(.headline)
                }
                Section {
                    ForEach(checks, id: \.id) { check in
                        CheckRow(check: check)
                    }
                } footer: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Version \(appVersion)")
                        Text("Core: ZChatProtocol")
                    }
                }
            }
            .navigationTitle("ZChat")
        }
    }
}

private struct CheckRow: View {
    let check: SelfTestCheck

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: check.passed ? "checkmark.circle.fill" : "xmark.octagon.fill")
                .foregroundStyle(check.passed ? Color.green : Color.red)
                .imageScale(.large)
                .accessibilityLabel(check.passed ? "Passed" : "Failed")
            VStack(alignment: .leading, spacing: 2) {
                Text(check.title)
                Text(check.detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
