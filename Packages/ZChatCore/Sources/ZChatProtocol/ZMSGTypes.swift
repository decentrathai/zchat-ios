// PAR-0002: value types of the ZMSG codec (UI/screen/chat/model/ZMSGProtocol.kt :1761-1973, GroupModels.kt:40-57 at
// 479a084d3).

public enum ZMSGError: Error, Equatable, Sendable {
    /// validateConvId, ZMSGProtocol.kt:130-137.
    case invalidConversationId
    /// :516, :557; `count` is the number of parts packing produced.
    case tooManyChunks(count: Int)
    /// :524; a single INIT memo over 512 bytes, `bytes` its UTF-8 size.
    case memoTooLong(bytes: Int)
}

public enum UnknownReason: Sendable, Equatable {
    case notZmsgFormat, malformedMessage, hashNotInCache, versionMismatch
}

public enum MessageType: Sendable, Equatable {
    case regular, reaction, readReceipt, reply, status, timeLock, unlock, paymentRequest, group
}

/// GroupModels.kt:40-57; the raw value is the wire code.
public enum GroupMessageType: String, Sendable, Equatable, CaseIterable {
    case groupCreate = "GC", groupInvite = "GI", groupAccept = "GA", groupLeave = "GL", groupKick = "GK",
         groupMsg = "GM", groupKey = "GY", groupInfo = "GF", groupKeyRequest = "GR", groupMember = "GP",
         groupRosterQuery = "GQ"

    /// `fromCode`, compared unit for unit (Swift `==` on String would accept canonical equivalents).
    static func fromCode(_ code: UTF16Units) -> GroupMessageType? {
        allCases.first { KS.units($0.rawValue) == code }
    }
}

/// ZMSGProtocol.kt:1761-1773.
public struct ParsedMessage: Sendable, Equatable {
    public var senderAddress: String?
    public var senderHash: String?
    public var message: String
    public var isUnknownSender: Bool
    public var reason: UnknownReason?
    public var replyToTxId: String?
    public var conversationId: String?
    public var messageType: MessageType
    public var groupId: String?
    public var groupMessageType: GroupMessageType?

    public init(senderAddress: String?, senderHash: String?, message: String, isUnknownSender: Bool,
                reason: UnknownReason?, replyToTxId: String? = nil, conversationId: String? = nil,
                messageType: MessageType = .regular, groupId: String? = nil,
                groupMessageType: GroupMessageType? = nil) {
        self.senderAddress = senderAddress
        self.senderHash = senderHash
        self.message = message
        self.isUnknownSender = isUnknownSender
        self.reason = reason
        self.replyToTxId = replyToTxId
        self.conversationId = conversationId
        self.messageType = messageType
        self.groupId = groupId
        self.groupMessageType = groupMessageType
    }
}

/// ZMSGProtocol.kt:478-502.
public struct ParsedADDRMessage: Sendable, Equatable {
    public var conversationId: String
    public var oldSenderHash: String
    public var newAddress: String
    public var signature: String

    public init(conversationId: String, oldSenderHash: String, newAddress: String, signature: String) {
        self.conversationId = conversationId
        self.oldSenderHash = oldSenderHash
        self.newAddress = newAddress
        self.signature = signature
    }
}

/// The (convId, payload) pair of a KEX or KEXACK memo (ZMSGProtocol.kt:383-429).
public struct KexEnvelope: Sendable, Equatable {
    public var conversationId: String
    public var payload: String

    public init(conversationId: String, payload: String) {
        self.conversationId = conversationId
        self.payload = payload
    }
}

/// The two members of Android's AddressCache that parsing uses (ZMSGProtocol.kt:1970).
public protocol ZMSGAddressCache {
    mutating func cacheAddress(hash: String, address: String)
    func getAddress(hash: String) -> String?
}
