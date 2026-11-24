// PAR-0003 (iOS app shell T0-pre, register IOSP-18): the self-check the T0-pre diagnostics screen shows.
// Pure and Foundation-free: the same `run()` gives the same answers on the iPhone (CryptoKit branch of SHA256.swift)
// and on Linux CI (swift-crypto branch). Every expected value is compared here; the caller only reads `passed`.
// A `detail` holds at most a 16-hex hash prefix or the generated conversation id, never an address.

public struct SelfTestCheck: Sendable, Equatable {
    public let id: String
    public let title: String
    public let passed: Bool
    public let detail: String
}

public enum ZChatSelfTest {
    /// The five checks, in this order: sha256-abc, address-hash, v4-init-roundtrip, chunk-roundtrip, conversation-id.
    public static func run() -> [SelfTestCheck] {
        [sha256Abc(), addressHash(), v4InitRoundtrip(), chunkRoundtrip(), conversationId()]
    }

    /// FIPS 180-2 example: SHA-256 of UTF-8 "abc".
    private static func sha256Abc() -> SelfTestCheck {
        let expectedDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        let got = lowercaseHex(sha256(Array("abc".utf8)))
        let ok = Array(got.utf8) == Array(expectedDigest.utf8)
        return SelfTestCheck(id: "sha256-abc", title: "SHA-256 test vector", passed: ok,
                             detail: ok ? "digest of \"abc\" matches FIPS 180-2" : "digest starts \(prefix16(got))")
    }

    /// generateAddressHash on the public test string "abc" (ZMSGContractTests.swift:247).
    private static func addressHash() -> SelfTestCheck {
        let expectedHash = "ba7816bf8f01cfea"
        let got = ZMSGProtocol.generateAddressHash("abc")
        let ok = Array(got.utf8) == Array(expectedHash.utf8)
        return SelfTestCheck(id: "address-hash", title: "Address hash", passed: ok,
                             detail: "hash of \"abc\" is \(prefix16(got))")
    }

    /// createV4InitMessage, then parseMemo on a fresh cache: text and conversation id come back byte-exact.
    private static func v4InitRoundtrip() -> SelfTestCheck {
        let id = "v4-init-roundtrip"
        let title = "ZMSG v4 INIT round trip"
        let convId = "SELFTEST"
        let text = "ZChat T0-pre self-check"
        do {
            let memo = try ZMSGProtocol.createV4InitMessage(convId: convId, senderAddress: syntheticSender,
                                                            message: text)
            var cache = SelfTestAddressCache()
            let parsed = ZMSGProtocol.parseMemo(memo, addressCache: &cache)
            let textOk = Array(parsed.message.utf8) == Array(text.utf8)
            let convOk = parsed.conversationId.map { Array($0.utf8) == Array(convId.utf8) } ?? false
            let ok = textOk && convOk
            return SelfTestCheck(id: id, title: title, passed: ok,
                                 detail: ok ? "conv \(convId), \(text.utf8.count) bytes back exactly"
                                     : "text \(textOk ? "ok" : "differs"), conv id \(convOk ? "ok" : "differs")")
        } catch {
            return SelfTestCheck(id: id, title: title, passed: false, detail: "INIT builder refused the input")
        }
    }

    /// A reply over the 462-byte first-chunk budget, with an emoji forced across the boundary and a combining mark:
    /// createChunkedV4ReplyMessages gives at least 2 memos and reassembleChunks gives the text back byte-exact.
    private static func chunkRoundtrip() -> SelfTestCheck {
        let id = "chunk-roundtrip"
        let title = "Chunked reply round trip"
        let text = String(repeating: "a", count: 460) + "\u{1F600}" + "e\u{301}" + " T0-pre"
        do {
            let memos = try ZMSGProtocol.createChunkedV4ReplyMessages(convId: "SELFTEST",
                                                                      senderAddress: syntheticSender, message: text)
            var cache = SelfTestAddressCache()
            let parsed = ZMSGProtocol.reassembleChunks(memos, addressCache: &cache)
            let textOk = parsed.map { Array($0.message.utf8) == Array(text.utf8) } ?? false
            let ok = memos.count >= 2 && textOk
            return SelfTestCheck(id: id, title: title, passed: ok,
                                 detail: "\(memos.count) memos, \(text.utf8.count) bytes, "
                                     + (parsed == nil ? "not reassembled" : (textOk ? "back exactly" : "differs")))
        } catch {
            return SelfTestCheck(id: id, title: title, passed: false, detail: "chunk builder refused the input")
        }
    }

    /// generateConversationId: 8 scalars, all in CONV_ID_CHARS.
    private static func conversationId() -> SelfTestCheck {
        let alphabet = Array(ZMSGConstants.convIdChars.unicodeScalars)
        let got = ZMSGProtocol.generateConversationId()
        let ok = got.unicodeScalars.count == ZMSGConstants.convIdLength
            && got.unicodeScalars.allSatisfy { alphabet.contains($0) }
        return SelfTestCheck(id: "conversation-id", title: "Conversation id", passed: ok,
                             detail: ok ? "generated \(got)" : "generated id has the wrong form")
    }

    /// Plainly synthetic, not shaped like any Zcash address; never put in a detail.
    private static let syntheticSender = "t0pre-selfcheck-sender"

    private static func prefix16(_ s: String) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.prefix(16)))
    }
}

/// The two cache members parsing uses, held only for one check.
private struct SelfTestAddressCache: ZMSGAddressCache {
    var entries: [String: String] = [:]

    mutating func cacheAddress(hash: String, address: String) { entries[hash] = address }

    func getAddress(hash: String) -> String? { entries[hash] }
}
