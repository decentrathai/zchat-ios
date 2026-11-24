// PAR-0002: Kotlin String semantics over UTF-16 code units (UNICODE RULE, ZMSGContractTests.swift).
// Android works on Kotlin Strings, so every index, indexOf, startsWith, split, trim and length in the ported code is
// over UTF-16 units, never over Swift Characters (grapheme clusters) and never with Swift's canonical-equivalence `==`.
// Every split in this module happens at an ASCII delimiter or after a whole prefix, so decoding a piece back to a
// String never meets a lone surrogate and is lossless.

typealias UTF16Units = [UInt16]

enum KS {
    static let pipe: UInt16 = 0x7C   // '|'
    static let slash: UInt16 = 0x2F  // '/'
    static let colon: UInt16 = 0x3A  // ':'

    static func units(_ s: String) -> UTF16Units { Array(s.utf16) }

    static func string(_ u: UTF16Units) -> String { String(decoding: u, as: UTF16.self) }

    /// Kotlin `startsWith(prefix)`.
    static func startsWith(_ u: UTF16Units, _ prefix: UTF16Units) -> Bool { u.starts(with: prefix) }

    /// Kotlin `removePrefix(prefix)`.
    static func removePrefix(_ u: UTF16Units, _ prefix: UTF16Units) -> UTF16Units {
        u.starts(with: prefix) ? Array(u.dropFirst(prefix.count)) : u
    }

    /// Kotlin `indexOf(char)`: the offset of the first match, -1 if none.
    static func indexOf(_ u: UTF16Units, _ c: UInt16) -> Int { u.firstIndex(of: c) ?? -1 }

    /// Kotlin `substring(from, to)`.
    static func substring(_ u: UTF16Units, _ from: Int, _ to: Int) -> UTF16Units { Array(u[from..<to]) }

    /// Kotlin `substring(from)`.
    static func substring(_ u: UTF16Units, _ from: Int) -> UTF16Units { Array(u[from..<u.count]) }

    /// Kotlin `split(delimiter, limit)`: empty fields are kept, trailing ones too; `limit` 0 means no limit, otherwise
    /// at most `limit` parts and the last part holds the rest unsplit.
    static func split(_ u: UTF16Units, _ delimiter: UInt16, limit: Int = 0) -> [UTF16Units] {
        var parts: [UTF16Units] = []
        var start = 0
        for i in 0..<u.count where u[i] == delimiter {
            if limit > 0 && parts.count == limit - 1 { break }
            parts.append(Array(u[start..<i]))
            start = i + 1
        }
        parts.append(Array(u[start..<u.count]))
        return parts
    }

    /// A character of ZMSGConstants.CONV_ID_CHARS (A-Z, 0-9).
    static func isConvIdChar(_ c: UInt16) -> Bool { (c >= 0x41 && c <= 0x5A) || (c >= 0x30 && c <= 0x39) }

    /// `it in '0'..'9' || it in 'a'..'f'` (ASCII only).
    static func isLowerHexAscii(_ c: UInt16) -> Bool { (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) }

    /// Kotlin `Char.isDigit()` on the JVM: general category Nd (any script). A surrogate unit is never a digit.
    static func isDigit(_ c: UInt16) -> Bool {
        guard let s = Unicode.Scalar(c) else { return false }
        return s.properties.generalCategory == .decimalNumber
    }

    /// `Character.digit(c, 10)` as Kotlin's `toIntOrNull` uses it on the JVM: the value of an Nd character, else nil.
    static func digit(_ c: UInt16) -> Int? {
        guard let s = Unicode.Scalar(c), s.properties.generalCategory == .decimalNumber,
              let v = s.properties.numericValue else { return nil }
        let d = Int(v)
        return (d >= 0 && d <= 9) ? d : nil
    }

    /// Kotlin `Char.isWhitespace()` on the JVM (`Character.isWhitespace || Character.isSpaceChar`): U+0009-U+000D,
    /// U+001C-U+001F and the categories Zs, Zl, Zp. (Unlike Unicode White_Space it has U+001C-U+001F, not U+0085.)
    static func isWhitespace(_ c: UInt16) -> Bool {
        if (c >= 0x09 && c <= 0x0D) || (c >= 0x1C && c <= 0x1F) { return true }
        guard let s = Unicode.Scalar(c) else { return false }
        switch s.properties.generalCategory {
        case .spaceSeparator, .lineSeparator, .paragraphSeparator: return true
        default: return false
        }
    }

    /// Kotlin `trim()`.
    static func trim(_ u: UTF16Units) -> UTF16Units {
        var start = 0
        var end = u.count
        while start < end && isWhitespace(u[start]) { start += 1 }
        while end > start && isWhitespace(u[end - 1]) { end -= 1 }
        return Array(u[start..<end])
    }

    /// Kotlin `isBlank()`.
    static func isBlank(_ u: UTF16Units) -> Bool { u.allSatisfy { isWhitespace($0) } }

    /// Kotlin `toIntOrNull()` (32-bit Int; optional leading '+' or '-'; JVM digits of any script).
    static func toIntOrNull(_ u: UTF16Units) -> Int? {
        guard let r = parseSigned(u, magnitudeMax: UInt64(Int32.max)) else { return nil }
        return r.negative ? -Int(r.magnitude) : Int(r.magnitude)
    }

    /// Kotlin `toLongOrNull()` (64-bit).
    static func toLongOrNull(_ u: UTF16Units) -> Int64? {
        guard let r = parseSigned(u, magnitudeMax: UInt64(Int64.max)) else { return nil }
        return r.negative ? Int64(bitPattern: 0 &- r.magnitude) : Int64(r.magnitude)
    }

    private static func parseSigned(_ u: UTF16Units, magnitudeMax: UInt64) -> (negative: Bool, magnitude: UInt64)? {
        if u.isEmpty { return nil }
        var start = 0
        var negative = false
        let first = u[0]
        if first < 0x30 {  // below '0': a sign or nothing valid
            if u.count == 1 { return nil }
            start = 1
            if first == 0x2D {
                negative = true
            } else if first != 0x2B {
                return nil
            }
        }
        let bound = negative ? magnitudeMax + 1 : magnitudeMax
        var magnitude: UInt64 = 0
        for i in start..<u.count {
            guard let d = digit(u[i]) else { return nil }
            let (m1, o1) = magnitude.multipliedReportingOverflow(by: 10)
            let (m2, o2) = m1.addingReportingOverflow(UInt64(d))
            if o1 || o2 || m2 > bound { return nil }
            magnitude = m2
        }
        return (negative, magnitude)
    }
}
