// PAR-0002: the one place ZChatProtocol computes a hash. CryptoKit on Apple, apple/swift-crypto on Linux
// (plan IOS_PLAN_FINAL.md:219, annex A2). Android: MessageDigest.getInstance("SHA-256"), ZMSGProtocol.kt:146-151.
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// SHA-256 digest (32 bytes) of `bytes`.
func sha256(_ bytes: [UInt8]) -> [UInt8] {
    Array(SHA256.hash(data: bytes))
}

/// Lowercase hex, as Kotlin `joinToString("") { "%02x".format(it) }`.
func lowercaseHex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
    let digits: [UInt8] = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    for b in bytes {
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 0x0F)])
    }
    return String(decoding: out, as: UTF8.self)
}
