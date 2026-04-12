// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Resolves keys from environment variables.
/// Variables are named as PREFIX_REF (uppercase, hyphens replaced with underscores).
public final class EnvProvider: KeyProvider {
    private let prefix: String

    /// Creates a provider that reads keys from env vars with the given prefix.
    public init(prefix: String = "") {
        self.prefix = prefix
    }

    public func resolve(ref: String) throws -> KeyRecord {
        let varName = envVarName(ref: ref)
        guard let value = ProcessInfo.processInfo.environment[varName], !value.isEmpty else {
            throw KeychainError.keyNotFound("env var \(varName) not set")
        }
        guard let material = hexDecode(value.trimmingCharacters(in: .whitespaces)) else {
            throw KeychainError.providerError("invalid hex in env var \(varName)")
        }
        return KeyRecord(
            ref: ref,
            version: 1,
            status: .active,
            material: material
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        // env vars don't support versioning
        return try resolve(ref: ref)
    }

    private func envVarName(ref: String) -> String {
        let name = ref.replacingOccurrences(of: "-", with: "_").uppercased()
        if prefix.isEmpty {
            return name
        }
        return "\(prefix)_\(name)"
    }
}

/// Decode a hex string to Data, returning nil on failure.
internal func hexDecode(_ hex: String) -> Data? {
    let chars = Array(hex)
    guard chars.count % 2 == 0 else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(chars.count / 2)
    for i in stride(from: 0, to: chars.count, by: 2) {
        guard let byte = UInt8(String(chars[i...i+1]), radix: 16) else {
            return nil
        }
        bytes.append(byte)
    }
    return Data(bytes)
}

/// Encode Data to a lowercase hex string.
internal func hexEncode(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}
