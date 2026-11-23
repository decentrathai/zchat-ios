// PAR-0002: reassembly of the chunked memos of one transaction as Android 2.13.0 does it.
// Census CENSUS1_WIRE_v2.13.0.md §1.4. Android lines: UI/screen/chat/model/ZMSGProtocol.kt at 479a084d3:
//   reassembleChunks :1224-1323, parseChunkInfo (v3c) :1328-1431, parseV4ChunkInfo :1440-1534.
// Contract: see ZMSGContractTests.swift.

import Testing
@testable import ZChatProtocol

@Suite("ZMSG reassembly: v4 chunks")
struct ZMSGV4ReassemblyTests {
    let h = "ba7816bf8f01cfea"   // generateAddressHash("abc"), FIPS 180-2 vector

    // ZMSGProtocol.kt:1269-1276: an INIT first chunk gives the address, its hash, and caches hash -> address, so a
    // later reply with that hash resolves. provisional (typed from code)
    @Test func initReassemblyCachesTheSenderForLaterReplies() throws {
        var cache = TestAddressCache()
        let initChunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.mainnetConvId, senderAddress: Fixture.mainnetUA, message: rep("a", 700))
        let first = try reassembled(initChunks, &cache)
        let hash = ZMSGProtocol.generateAddressHash(Fixture.mainnetUA)
        #expect(first == ParsedMessage(
            senderAddress: Fixture.mainnetUA, senderHash: hash, message: rep("a", 700),
            isUnknownSender: false, reason: nil, conversationId: Fixture.mainnetConvId))
        #expect(cache.getAddress(hash: hash) == Fixture.mainnetUA)

        let replyChunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: Fixture.mainnetConvId, senderAddress: Fixture.mainnetUA, message: rep("b", 600))
        let reply = try reassembled(replyChunks, &cache)
        #expect(reply.senderAddress == Fixture.mainnetUA)
        #expect(reply.senderHash == hash)
    }

    // ZMSGProtocol.kt:1282-1319: a v4 reply whose hash is not cached is NOT unknown (it resolves via the conv id):
    // address nil, hash kept, reason nil. provisional (typed from code)
    @Test func uncachedV4ReplyIsResolvedByConversationId() throws {
        var cache = TestAddressCache()
        let chunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: "CONV0001", senderAddress: "abc", message: rep("z", 500))
        let r = try reassembled(chunks, &cache)
        #expect(r == ParsedMessage(
            senderAddress: nil, senderHash: h, message: rep("z", 500),
            isUnknownSender: false, reason: nil, conversationId: "CONV0001"))
    }

    // ZMSGProtocol.kt:1242, :1297: sorted by index, joined with no separator; output order in the transaction is
    // irrelevant (Orchard shuffles outputs). All 6 orders of 3 chunks. provisional (typed from code)
    @Test func everyOutputOrderGivesTheSameMessage() throws {
        let chunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: "CONV0001", senderAddress: "abc", message: rep("a", 462) + rep("b", 485) + "c|d")
        #expect(chunks.count == 3)
        let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]
        for order in orders {
            var cache = TestAddressCache()
            let r = try reassembled(order.map { chunks[$0] }, &cache)
            #expect(bytes(r.message) == bytes(rep("a", 462) + rep("b", 485) + "c|d"))
        }
    }

    // ZMSGProtocol.kt:1253-1261: exactly the set {1..N}. A missing or duplicated index gives nil.
    // provisional (typed from code)
    @Test func incompleteOrDuplicatedSetsAreRefused() throws {
        let c = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: "CONV0001", senderAddress: "abc", message: rep("a", 1000))
        #expect(c.count == 3)
        #expect(reassembledOrNil([c[0], c[2]]) == nil)
        #expect(reassembledOrNil([c[0]]) == nil)
        #expect(reassembledOrNil([c[1], c[2]]) == nil)
        #expect(reassembledOrNil([c[0], c[0], c[2]]) == nil)
        #expect(reassembledOrNil([c[0], c[1], c[2], c[2]]) == nil)
        #expect(reassembledOrNil([c[0], c[0]]) == nil)
    }

    // QUIRK, ZMSGProtocol.kt:1253: only the total of chunk 1 is read; the other chunks' totals are not compared.
    // "1/2" + "2/3" is accepted as a complete 2-chunk message. provisional (typed from code)
    @Test func totalsOfLaterChunksAreNotCrossChecked() throws {
        var cache = TestAddressCache()
        let r = try reassembled(["ZMSG|v4c|2/3|CONT|cd", "ZMSG|v4c|1/2|CONV0001|\(h)|ab"], &cache)
        #expect(bytes(r.message) == bytes("abcd"))
    }

    // ZMSGProtocol.kt:1440-1534 (and :1451-1459 bounds 1 <= i <= N <= 1000): each of these first chunks is refused
    // by the chunk parser, so on its own it reassembles to nil. provisional (typed from code)
    @Test(arguments: [
        "ZMSG|v4c|0/1|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|2/1|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|1/0|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|-1/1|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|1/1001|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|a/1|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|1/|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|11|CONV0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|1/1",
        "ZMSG|v4c|1/1|CONV001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|1/1|CONV00011|ba7816bf8f01cfea|a",
        "ZMSG|v4c|1/1|conv0001|ba7816bf8f01cfea|a",
        "ZMSG|v4c|1/1|CONV0001",
        "ZMSG|v4c|1/1|CONV0001|INIT|u1addr",
    ])
    func malformedChunkHeadersAreDropped(memo: String) {
        #expect(reassembledOrNil([memo]) == nil)
    }

    // A dropped malformed chunk leaves the set incomplete even when a valid sibling is present (ZMSGProtocol.kt:1240,
    // :1253-1261; "CONTX|" is not the CONT marker and fails the conv id rule, :1465-1478). provisional (typed from
    // code)
    @Test func aDroppedChunkLeavesTheSetIncomplete() {
        #expect(reassembledOrNil(["ZMSG|v4c|0/2|CONV0001|\(h)|a", "ZMSG|v4c|2/2|CONT|b"]) == nil)
        #expect(reassembledOrNil(["ZMSG|v4c|1/2|CONV0001|\(h)|a", "ZMSG|v4c|2/2|CONTX|b"]) == nil)
    }

    // The builder never emits "1/1" (:518, :559), but the parser accepts it (bounds at ZMSGProtocol.kt:1456 are
    // inclusive). The upper bound 1000 is a valid total; a lone "1/1000" is incomplete (:1254).
    // provisional (typed from code)
    @Test func boundsAreInclusive() throws {
        var cache = TestAddressCache()
        let one = try reassembled(["ZMSG|v4c|1/1|CONV0001|\(h)|a"], &cache)
        #expect(one == ParsedMessage(
            senderAddress: nil, senderHash: h, message: "a", isUnknownSender: false, reason: nil,
            conversationId: "CONV0001"))
        #expect(reassembledOrNil(["ZMSG|v4c|1/1000|CONV0001|\(h)|a"]) == nil)
    }

    // ZMSGProtocol.kt:1520-1529: a first chunk with no 12/16 lowercase-hex hash is the legacy hashless form; its whole
    // rest is text. Uppercase hex is NOT a hash (ASCII a-f only, :1507-1508). provisional (typed from code)
    @Test func hashlessAndUppercaseFirstChunksAreText() throws {
        var cache = TestAddressCache()
        let hashless = try reassembled(["ZMSG|v4c|1/2|CONV0001|hello ", "ZMSG|v4c|2/2|CONT|world"], &cache)
        #expect(hashless == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: "hello world", isUnknownSender: false, reason: nil,
            conversationId: "CONV0001"))
        let upper = try reassembled(["ZMSG|v4c|1/2|CONV0001|BA7816BF8F01CFEA|he", "ZMSG|v4c|2/2|CONT|y"], &cache)
        #expect(bytes(upper.message) == bytes("BA7816BF8F01CFEA|hey"))
        #expect(upper.senderHash == nil)
        let legacy = try reassembled(["ZMSG|v4c|1/2|CONV0001|ba7816bf8f01|he", "ZMSG|v4c|2/2|CONT|y"], &cache)
        #expect(legacy.senderHash == "ba7816bf8f01")
        #expect(bytes(legacy.message) == bytes("hey"))
    }

    // ZMSGProtocol.kt:1471, :1297: CONT parts are taken raw (pipes and empty parts included). provisional (typed from
    // code)
    @Test func continuationPartsAreRaw() throws {
        var cache = TestAddressCache()
        let r = try reassembled([
            "ZMSG|v4c|1/3|CONV0001|\(h)|a", "ZMSG|v4c|2/3|CONT|", "ZMSG|v4c|3/3|CONT|x|y||",
        ], &cache)
        #expect(bytes(r.message) == bytes("ax|y||"))
    }

    // QUIRK, ZMSGProtocol.kt:1282-1319: if index 1 is itself a CONT chunk, there is no conv id and no sender:
    // unknown, HASH_NOT_IN_CACHE, text still joined. provisional (typed from code)
    @Test func aContinuationAtIndexOneIsAnUnknownSender() throws {
        var cache = TestAddressCache()
        let r = try reassembled(["ZMSG|v4c|1/2|CONT|a", "ZMSG|v4c|2/2|CONT|b"], &cache)
        #expect(r == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: "ab", isUnknownSender: true, reason: .hashNotInCache))
    }
}

@Suite("ZMSG reassembly: transaction shapes")
struct ZMSGReassemblyShapeTests {
    // ZMSGProtocol.kt:1225: no memos, nil. :1230-1236: no chunked memo -> exactly one memo is parsed with parseMemo,
    // two or more give nil. provisional (typed from code)
    @Test func nonChunkedTransactions() {
        #expect(reassembledOrNil([]) == nil)
        let single = "ZMSG|v4|CONV0001|INIT|u1addr|hello"
        #expect(reassembledOrNil([single]) == parseOne(single))
        #expect(reassembledOrNil([single])?.senderAddress == "u1addr")
        #expect(reassembledOrNil(["plain"]) == parseOne("plain"))
        #expect(reassembledOrNil([single, "ZMSG|v4|CONV0001|ba7816bf8f01cfea|x"]) == nil)
        #expect(reassembledOrNil(["plain", "text"]) == nil)
    }

    // ZMSGProtocol.kt:1228: when chunks are present, every non-chunked memo beside them is ignored.
    // provisional (typed from code)
    @Test func strayNonChunkedMemosBesideChunksAreIgnored() throws {
        var cache = TestAddressCache()
        let r = try reassembled([
            "ZMSG|v4c|2/2|CONT|b", "hello", "ZMSG|v4|CONV0001|INIT|u1addr|x", "ZMSG|v4c|1/2|CONV0001|hashless a",
        ], &cache)
        #expect(bytes(r.message) == bytes("hashless ab"))
        #expect(r.senderAddress == nil)
        #expect(cache.getAddress(hash: ZMSGProtocol.generateAddressHash("u1addr")) == nil)
    }
}

@Suite("ZMSG reassembly: legacy v3 chunks (parse only)")
struct ZMSGV3ReassemblyTests {
    // ZMSGProtocol.kt:1358-1371, :1269-1276: v3c INIT first chunk, any output order. provisional (typed from code)
    @Test func v3InitChunks() throws {
        var cache = TestAddressCache()
        let r = try reassembled(["ZMSG|v3c|2/2|CONT|lo", "ZMSG|v3c|1/2|INIT|u1addr|hel"], &cache)
        let hash = ZMSGProtocol.generateAddressHash("u1addr")
        #expect(r == ParsedMessage(
            senderAddress: "u1addr", senderHash: hash, message: "hello", isUnknownSender: false, reason: nil))
        #expect(cache.getAddress(hash: hash) == "u1addr")
    }

    // ZMSGProtocol.kt:1418-1429, :1277-1281: v3c hash first chunk (any text before the first '|' is the hash).
    // Unresolved -> unknown HASH_NOT_IN_CACHE; resolved once cached. provisional (typed from code)
    @Test func v3HashChunks() throws {
        var cache = TestAddressCache()
        let memos = ["ZMSG|v3c|1/2|abcdef012345|he", "ZMSG|v3c|2/2|CONT|llo"]
        let unknown = try reassembled(memos, &cache)
        #expect(unknown == ParsedMessage(
            senderAddress: nil, senderHash: "abcdef012345", message: "hello", isUnknownSender: true,
            reason: .hashNotInCache))
        cache.cacheAddress(hash: "abcdef012345", address: "u1known")
        let known = try reassembled(memos, &cache)
        #expect(known.senderAddress == "u1known")
        #expect(known.isUnknownSender == false)
        #expect(known.reason == nil)
    }

    // ZMSGProtocol.kt:1372-1407: v3c REF first chunks carry the referenced txid (replyToTxId).
    // provisional (typed from code)
    @Test func v3RefChunks() throws {
        var cache = TestAddressCache()
        let byHash = try reassembled(["ZMSG|v3c|1/2|REF|tx1|abcdef012345|he", "ZMSG|v3c|2/2|CONT|y"], &cache)
        #expect(byHash == ParsedMessage(
            senderAddress: nil, senderHash: "abcdef012345", message: "hey", isUnknownSender: true,
            reason: .hashNotInCache, replyToTxId: "tx1"))
        let byInit = try reassembled(["ZMSG|v3c|1/2|REF|tx1|INIT|u1addr|he", "ZMSG|v3c|2/2|CONT|y"], &cache)
        #expect(byInit == ParsedMessage(
            senderAddress: "u1addr", senderHash: ZMSGProtocol.generateAddressHash("u1addr"), message: "hey",
            isUnknownSender: false, reason: nil, replyToTxId: "tx1"))
    }

    // ZMSGProtocol.kt:1340-1354, :1362-1363, :1375-1376: malformed v3c first chunks are dropped. provisional (typed
    // from code)
    @Test(arguments: [
        "ZMSG|v3c|0/1|abcdef012345|a",
        "ZMSG|v3c|1/1001|abcdef012345|a",
        "ZMSG|v3c|1/1|INIT|u1addr",
        "ZMSG|v3c|1/1|REF|tx1",
        "ZMSG|v3c|1/1|nopipe",
        "ZMSG|v3c|1|abcdef012345|a",
    ])
    func malformedV3ChunksAreDropped(memo: String) {
        #expect(reassembledOrNil([memo]) == nil)
    }
}
