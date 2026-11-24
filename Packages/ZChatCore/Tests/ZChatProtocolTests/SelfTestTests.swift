// PAR-0003 (iOS app shell T0-pre, register IOSP-18): the diagnostics list on the app's first screen.
//
// The T0-pre screen shows the result of a pure ZChatCore function, so the iPhone build (CryptoKit branch of
// SHA256.swift) proves it gives the same answers as the Linux build (swift-crypto branch) that CI runs. These tests
// run on Linux; the app runs the same `run()` on device.
//
// ============================================================================================================
// API CONTRACT (module ZChatProtocol, package Packages/ZChatCore). Pure Swift, no UI, no I/O, Sendable values.
// ============================================================================================================
//
// public struct SelfTestCheck: Sendable, Equatable {
//     public let id: String        // stable machine id, see the table below
//     public let title: String     // short human title, non-empty
//     public let passed: Bool
//     public let detail: String    // short human string, at most 80 Unicode scalars, no secret, no full address
// }
//
// public enum ZChatSelfTest {
//     public static func run() -> [SelfTestCheck]
// }
//
// `run()` returns exactly these checks, in this order. Every expected value is compared INSIDE `run()`; the test only
// sees `passed`. Every check passes on a correct build.
//
//   1. "sha256-abc"         SHA-256 of UTF-8 "abc" through the package's own hashing (SHA256.swift `sha256`) equals
//                           the FIPS 180-2 example digest
//                           ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
//   2. "address-hash"       ZMSGProtocol.generateAddressHash("abc") == "ba7816bf8f01cfea" (the public test string
//                           and value of ZMSGContractTests.swift:247; first 8 bytes of the FIPS vector above). No real
//                           address is used.
//   3. "v4-init-roundtrip"  createV4InitMessage(convId:senderAddress:message:) with a fixed synthetic sender, convId
//                           and text, then parseMemo on a fresh cache: message and conversationId come back
//                           byte-exact (compared as UTF-8 bytes).
//   4. "chunk-roundtrip"    a fixed text that needs more than one chunk and contains an emoji and a combining mark
//                           (e.g. "e\u{301}"): createChunkedV4ReplyMessages gives at least 2 memos, and
//                           reassembleChunks on a fresh cache gives the text back byte-exact (UTF-8 bytes).
//   5. "conversation-id"    generateConversationId() is 8 Unicode scalars, all in ZMSGConstants.convIdChars (the
//                           rule of ZMSGContractTests.generatedConversationIdsAreEightAlphabetCharacters).
//
// `detail` never contains a secret or a full address (a 16-hex hash prefix is allowed). It may contain the generated
// conversation id, so tests compare only `id` and `passed` across calls, never `detail`.
// ============================================================================================================

import Testing
import ZChatProtocol  // plain import on purpose: the app uses this API, so it must be public.

@Suite("ZChatCore self-check for the T0-pre diagnostics screen (PAR-0003)")
struct ZChatSelfTestTests {
    static let expectedIds = ["sha256-abc", "address-hash", "v4-init-roundtrip", "chunk-roundtrip", "conversation-id"]

    @Test func returnsTheFiveChecksInOrder() {
        #expect(ZChatSelfTest.run().map(\.id) == Self.expectedIds)
    }

    @Test func everyCheckPassesOnThisBuild() {
        for check in ZChatSelfTest.run() {
            #expect(check.passed, "self-check \(check.id) failed: \(check.detail)")
        }
    }

    @Test func titlesAreNonEmpty() {
        for check in ZChatSelfTest.run() {
            #expect(!check.title.unicodeScalars.isEmpty, "self-check \(check.id) has an empty title")
        }
    }

    @Test func detailsAreShort() {
        for check in ZChatSelfTest.run() {
            #expect(check.detail.unicodeScalars.count <= 80, "self-check \(check.id) detail is over 80 scalars")
        }
    }

    @Test func idsAndResultsAreDeterministic() {
        let first = ZChatSelfTest.run()
        let second = ZChatSelfTest.run()
        #expect(first.map(\.id) == second.map(\.id))
        #expect(first.map(\.passed) == second.map(\.passed))
    }
}
