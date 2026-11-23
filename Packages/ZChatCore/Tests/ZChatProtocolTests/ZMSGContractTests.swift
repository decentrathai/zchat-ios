// PAR-0002 (wire, area zmsg): ZMSG envelope, prefixes, memo chunking and reassembly, parse order as Android 2.13.0.
//
// Source of truth: ~/zchat-evidence/ios/census/CENSUS1_WIRE_v2.13.0.md section 1 (L1). Every Android citation below is
// at Android commit 479a084d3 (tag v2.13.0). Path abbreviations as in the census:
//   UI/ = ui-lib/src/main/java/co/electriccoin/zcash/ui/   T/ = ui-lib/src/test/java/co/electriccoin/zcash/ui/
// A case ported from an Android unit test names that test. A case typed from Android code (no Android test) is marked
// `// provisional (typed from code)` (plan D.6). Until the vector exporter exists (AGENTS.md rule 4) every literal in
// these files is provisional; literals computed offline by a code-point simulation of `packChunks` say so.
//
// ============================================================================================================
// API CONTRACT (module ZChatProtocol, package Packages/ZChatCore). Pure Swift, no Foundation needed, Sendable values.
// ============================================================================================================
//
// UNICODE RULE (binding): Android works on Kotlin Strings, i.e. UTF-16 code units. Every index, `indexOf('|')`,
// `startsWith`, `split` and `length` in the Android code is over UTF-16 units; budgets are over UTF-8 bytes of whole
// code points. The Swift implementation must therefore work on `unicodeScalars` / `utf8` / `utf16`, NEVER on
// `Character` (grapheme clusters): `"|\u{301}"` is one Character in Swift but two code points in Kotlin, and Swift
// `String ==` is canonical equivalence. Tests compare `Array(s.utf8)` wherever this matters.
//
// public enum ZMSGConstants {
//     static let maxMemoSize = 512                 // ZMSGConstants.kt:19
//     static let convIdLength = 8                  // :26
//     static let convIdChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"   // :29
//     static let hashLength = 12                   // :34 (legacy, parse only)
//     static let hashLengthNew = 16                // :39
//     static let maxChunks = 1000                  // ZMSGProtocol.kt:67
//     enum Prefixes {                              // :47-66
//         static let v4, v4c, v3, v3c, v2, group,
//                    reaction, receipt, status, timelock, unlock, request, file, disappear, modeChange, profile: String
//     }
//     enum Markers {                               // :74-80
//         static let initial ("INIT|"), cont, ref, reply, kex, kexAck, addr: String
//     }
//     enum ChunkSizes {                            // :105-124
//         static let v3Init = 340, v3ReplyFirst = 470, continuation = 485, v4Init = 330, v4ReplyFirst = 462
//     }
// }
//
// public enum ZMSGError: Error, Equatable, Sendable {
//     case invalidConversationId              // validateConvId, ZMSGProtocol.kt:130-137
//     case tooManyChunks(count: Int)          // :516, :557 (count = parts that packing produced)
//     case memoTooLong(bytes: Int)            // :524 single INIT memo over 512 bytes (bytes = its UTF-8 size)
// }
//
// public enum UnknownReason: Sendable, Equatable { case notZmsgFormat, malformedMessage, hashNotInCache, versionMismatch }
// public enum MessageType: Sendable, Equatable {
//     case regular, reaction, readReceipt, reply, status, timeLock, unlock, paymentRequest, group }
// public enum GroupMessageType: String, Sendable, Equatable {       // GroupModels.kt:40-57, raw value = wire code
//     case groupCreate = "GC", groupInvite = "GI", groupAccept = "GA", groupLeave = "GL", groupKick = "GK",
//          groupMsg = "GM", groupKey = "GY", groupInfo = "GF", groupKeyRequest = "GR", groupMember = "GP",
//          groupRosterQuery = "GQ"
// }
//
// public struct ParsedMessage: Sendable, Equatable {               // ZMSGProtocol.kt:1761-1773
//     public var senderAddress: String?
//     public var senderHash: String?
//     public var message: String
//     public var isUnknownSender: Bool
//     public var reason: UnknownReason?
//     public var replyToTxId: String?
//     public var conversationId: String?
//     public var messageType: MessageType
//     public var groupId: String?
//     public var groupMessageType: GroupMessageType?
//     public init(senderAddress: String?, senderHash: String?, message: String, isUnknownSender: Bool,
//                 reason: UnknownReason?, replyToTxId: String? = nil, conversationId: String? = nil,
//                 messageType: MessageType = .regular, groupId: String? = nil, groupMessageType: GroupMessageType? = nil)
// }
// public struct ParsedADDRMessage: Sendable, Equatable { conversationId, oldSenderHash, newAddress, signature: String }
// public struct KexEnvelope: Sendable, Equatable { public var conversationId: String; public var payload: String }
//
// public protocol ZMSGAddressCache {                               // ZMSGProtocol.kt:1970 (the two members parse uses)
//     mutating func cacheAddress(hash: String, address: String)
//     func getAddress(hash: String) -> String?
// }
//
// public enum ZMSGProtocol {
//     static func generateAddressHash(_ address: String) -> String          // :146-151 16 lowercase hex, SHA-256(UTF-8)
//     static func generateLegacyAddressHash(_ address: String) -> String    // :165-169 12 lowercase hex
//     static func isLegacyHash(_ hash: String) -> Bool                      // :157-159
//     static func generateConversationId() -> String                        // :179-184 (system CSPRNG)
//     static func v4InitFirstChunkBudget(senderAddress: String) -> Int      // :207-222
//     static func createV4InitMessage(convId: String, senderAddress: String, message: String) throws -> String
//     static func createV4ReplyMessage(convId: String, senderAddress: String, message: String) throws -> String
//     static func createV4KEXMessage(convId: String, senderAddress: String, kexPayload: String) throws -> String
//     static func createV4KEXAckMessage(convId: String, senderAddress: String, kexAckPayload: String) throws -> String
//     static func createV4ADDRMessage(convId: String, oldSenderAddress: String, newAddress: String,
//                                     signature: String) throws -> String
//     static func createChunkedV4InitMessages(convId: String, senderAddress: String, message: String) throws -> [String]
//     static func createChunkedV4ReplyMessages(convId: String, senderAddress: String, message: String) throws -> [String]
//     static func calculateV4ChunkCount(message: String, isInitMessage: Bool, senderAddress: String? = nil) -> Int
//     static func parseV4Init(_ memo: String) -> (address: String, message: String)?       // :261-277
//     static func parseV4InitConvId(_ memo: String) -> String?                             // :283-284
//     static func isKEXMessage(_ memo: String) -> Bool                                     // :328-335
//     static func isKEXAckMessage(_ memo: String) -> Bool                                  // :340-347
//     static func isADDRMessage(_ memo: String) -> Bool                                    // :463-470
//     static func parseKEXMessage(_ memo: String) -> KexEnvelope?                          // :383-403
//     static func parseKEXAckMessage(_ memo: String) -> KexEnvelope?                       // :411-429
//     static func parseADDRMessage(_ memo: String) -> ParsedADDRMessage?                   // :478-502
//     static func isChunkedMemo(_ memo: String) -> Bool                                    // :1539
//     static func isRecognizedZmsgEnvelope(_ memo: String) -> Bool                         // :778-788
//     static func parseMemo<C: ZMSGAddressCache>(_ memo: String, addressCache: inout C) -> ParsedMessage   // :674-767
//     static func reassembleChunks<C: ZMSGAddressCache>(_ memos: [String], addressCache: inout C) -> ParsedMessage?
//                                                                                          // :1224-1323
//     static func splitMemosByKind(_ memos: [String]) -> [[String]]                        // :349-375
// }
//
// Deliberately NOT in this contract: v2/v3 builders (iOS parses those formats, never emits them; no dormant code),
// special-message builders (ZREACT/ZRCPT/... are separate items), ZFILE/ZATT, the ZIP-321 URI, the contact code, group
// payloads, and anything for REMOTE_KILL_PREFIX (never compiled in on iOS). ZBOOT is parsed here only as far as
// parseMemo needs its convId (ZBootMessage.parse, UI/screen/chat/model/ZBootMessage.kt:71-127).
// ============================================================================================================

import Testing
@testable import ZChatProtocol

// MARK: - Shared test helpers

/// Mirrors the Android `TestAddressCache` of T/screen/chat/model/ZMSGChunkingEmojiIntegrityTest.kt:33-50.
struct TestAddressCache: ZMSGAddressCache {
    var entries: [String: String] = [:]

    mutating func cacheAddress(hash: String, address: String) { entries[hash] = address }

    func getAddress(hash: String) -> String? { entries[hash] }
}

struct ReassemblyReturnedNil: Error {}

/// `reassembleChunks` that must succeed. Kept outside `#expect`/`#require` so no `&` argument goes through a macro.
func reassembled(_ memos: [String], _ cache: inout TestAddressCache) throws -> ParsedMessage {
    guard let parsed = ZMSGProtocol.reassembleChunks(memos, addressCache: &cache) else {
        Issue.record("reassembleChunks returned nil")
        throw ReassemblyReturnedNil()
    }
    return parsed
}

/// `reassembleChunks` over a COPY of `cache` (no `inout`, so it is safe inside `#expect`).
func reassembledOrNil(_ memos: [String], cache: TestAddressCache = TestAddressCache()) -> ParsedMessage? {
    var copy = cache
    return ZMSGProtocol.reassembleChunks(memos, addressCache: &copy)
}

/// `parseMemo` that updates `cache` (call it outside macros).
func parseCaching(_ memo: String, _ cache: inout TestAddressCache) -> ParsedMessage {
    ZMSGProtocol.parseMemo(memo, addressCache: &cache)
}

/// `parseMemo` over a COPY of `cache` (no `inout`, so it is safe inside `#expect`).
func parseOne(_ memo: String, cache: TestAddressCache = TestAddressCache()) -> ParsedMessage {
    var copy = cache
    return ZMSGProtocol.parseMemo(memo, addressCache: &copy)
}

/// UTF-8 bytes of a string; byte-exact comparisons go through this (Swift `==` on String is canonical equivalence).
func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

/// UTF-8 byte length.
func byteLen(_ s: String) -> Int { s.utf8.count }

/// `String(repeating:count:)` shorthand.
func rep(_ s: String, _ n: Int) -> String { String(repeating: s, count: n) }

/// Synthetic public test addresses (no real address is used anywhere in these tests).
enum Fixture {
    /// T/screen/chat/model/ZMSGChunkingEmojiIntegrityTest.kt:52 (68 bytes).
    static let sender = "u1testsenderaddressforchunkingemojiintegrity000000000000000000000000"
    /// T/screen/chat/model/ZMSGChunkingEmojiIntegrityTest.kt:54.
    static let convId = "TESTCONV"
    /// T/screen/chat/model/ZMSGV4InitMainnetOverflowTest.kt:51.
    static let mainnetConvId = "TESTCV01"
    /// T/screen/chat/model/ZMSGV4InitMainnetOverflowTest.kt:54 ("u1" + 176 alphanumeric = 178 bytes).
    static let mainnetUA = "u1" + rep("a", 176)
    /// T/screen/chat/model/ZMSGV4InitMainnetOverflowTest.kt:57 (145 bytes).
    static let testnetUA = "utest1" + rep("b", 139)
    /// T/screen/chat/model/RetestGap08ZMSGProtocolZBootRoutingTest.kt:49-50.
    static let bootConvId = "ABCD1234"
    static let wellFormedBoot = "ZBOOT|v3|ABCD1234|" + rep("a", 64) + "|wss://r.example|0|c2ln"
}

// MARK: - Constants

@Suite("ZMSG constants as Android 2.13.0")
struct ZMSGConstantsTests {
    // UI/screen/chat/model/ZMSGConstants.kt:19, :26, :29, :34, :39; ZMSGProtocol.kt:67. provisional (typed from code)
    @Test func sizesAndConversationIdAlphabet() {
        #expect(ZMSGConstants.maxMemoSize == 512)
        #expect(ZMSGConstants.convIdLength == 8)
        #expect(bytes(ZMSGConstants.convIdChars) == bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
        #expect(ZMSGConstants.hashLength == 12)
        #expect(ZMSGConstants.hashLengthNew == 16)
        #expect(ZMSGConstants.maxChunks == 1000)
    }

    // ZMSGConstants.kt:47-66. provisional (typed from code)
    @Test func prefixesAreByteExact() {
        let p = ZMSGConstants.Prefixes.self
        #expect(bytes(p.v4) == bytes("ZMSG|v4|"))
        #expect(bytes(p.v4c) == bytes("ZMSG|v4c|"))
        #expect(bytes(p.v3) == bytes("ZMSG|v3|"))
        #expect(bytes(p.v3c) == bytes("ZMSG|v3c|"))
        #expect(bytes(p.v2) == bytes("ZMSG|v2|"))
        #expect(bytes(p.group) == bytes("ZMSG:3.0:GROUP:"))
        #expect(bytes(p.reaction) == bytes("ZREACT|"))
        #expect(bytes(p.receipt) == bytes("ZRCPT|"))
        #expect(bytes(p.status) == bytes("ZSTAT|"))
        #expect(bytes(p.timelock) == bytes("ZTL|"))
        #expect(bytes(p.unlock) == bytes("ZUNLOCK|"))
        #expect(bytes(p.request) == bytes("ZREQ|"))
        #expect(bytes(p.file) == bytes("ZFILE|"))
        #expect(bytes(p.disappear) == bytes("ZEXP|"))
        #expect(bytes(p.modeChange) == bytes("ZMODE|"))
        #expect(bytes(p.profile) == bytes("ZPROF|"))
    }

    // ZMSGConstants.kt:74-80. provisional (typed from code)
    @Test func markersAreByteExact() {
        let m = ZMSGConstants.Markers.self
        #expect(bytes(m.initial) == bytes("INIT|"))
        #expect(bytes(m.cont) == bytes("CONT|"))
        #expect(bytes(m.ref) == bytes("REF|"))
        #expect(bytes(m.reply) == bytes("RPL|"))
        #expect(bytes(m.kex) == bytes("KEX|"))
        #expect(bytes(m.kexAck) == bytes("KEXACK|"))
        #expect(bytes(m.addr) == bytes("ADDR|"))
    }

    // ZMSGConstants.kt:105-124. provisional (typed from code)
    @Test func chunkTextBudgets() {
        #expect(ZMSGConstants.ChunkSizes.v3Init == 340)
        #expect(ZMSGConstants.ChunkSizes.v3ReplyFirst == 470)
        #expect(ZMSGConstants.ChunkSizes.continuation == 485)
        #expect(ZMSGConstants.ChunkSizes.v4Init == 330)
        #expect(ZMSGConstants.ChunkSizes.v4ReplyFirst == 462)
    }
}

// MARK: - Hashes and conversation ids

@Suite("ZMSG sender hashes and conversation ids")
struct ZMSGHashTests {
    // ZMSGProtocol.kt:146-151: first 8 bytes of SHA-256(UTF-8 address), lowercase hex. Input "abc" is the FIPS 180-2
    // SHA-256 example (digest ba7816bf8f01cfea414140de5dae2223...), so this literal is a published value.
    // provisional (typed from code)
    @Test func senderHashIsFirstEightBytesOfSha256LowercaseHex() {
        #expect(bytes(ZMSGProtocol.generateAddressHash("abc")) == bytes("ba7816bf8f01cfea"))
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924... (published).
        #expect(bytes(ZMSGProtocol.generateAddressHash("")) == bytes("e3b0c44298fc1c14"))
    }

    // ZMSGProtocol.kt:165-169: legacy 6-byte form. provisional (typed from code)
    @Test func legacyHashIsFirstSixBytes() {
        #expect(bytes(ZMSGProtocol.generateLegacyAddressHash("abc")) == bytes("ba7816bf8f01"))
    }

    // ZMSGProtocol.kt:157-159: exactly 12 chars of 0-9 / a-f. provisional (typed from code)
    @Test func legacyHashRecogniser() {
        #expect(ZMSGProtocol.isLegacyHash("ba7816bf8f01"))
        #expect(!ZMSGProtocol.isLegacyHash("BA7816BF8F01"))
        #expect(!ZMSGProtocol.isLegacyHash("ba7816bf8f01cfea"))
        #expect(!ZMSGProtocol.isLegacyHash("ba7816bf8f0g"))
    }

    // ZMSGProtocol.kt:179-184: 8 characters drawn from CONV_ID_CHARS. provisional (typed from code)
    @Test func generatedConversationIdsAreEightAlphabetCharacters() {
        let alphabet = Set(ZMSGConstants.convIdChars.unicodeScalars)
        var seen = Set<String>()
        for _ in 0..<200 {
            let id = ZMSGProtocol.generateConversationId()
            #expect(id.unicodeScalars.count == 8)
            #expect(id.unicodeScalars.allSatisfy { alphabet.contains($0) })
            seen.insert(id)
        }
        // 36^8 ids: 200 draws colliding would mean the generator is not random.
        #expect(seen.count > 190)
    }

    // A generated id is accepted by every builder (validateConvId, :130-137). provisional (typed from code)
    @Test func generatedConversationIdPassesBuilderValidation() throws {
        let id = ZMSGProtocol.generateConversationId()
        let memo = try ZMSGProtocol.createV4ReplyMessage(convId: id, senderAddress: Fixture.sender, message: "x")
        #expect(memo.hasPrefix("ZMSG|v4|" + id + "|"))
    }
}
