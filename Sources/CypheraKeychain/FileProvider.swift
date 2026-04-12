// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Resolves keys from a JSON file.
public final class FileProvider: KeyProvider {
    private var records: [String: [KeyRecord]] = [:]

    /// Loads keys from a JSON file at the given path.
    public init(path: String) throws {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let config = try JSONDecoder().decode(FileConfig.self, from: data)

        for key in config.keys {
            guard let material = decodeKeyMaterial(key.material) else {
                throw KeychainError.providerError("key \(key.ref): could not decode material as hex or base64")
            }
            var tweak: Data?
            if let tweakStr = key.tweak, !tweakStr.isEmpty {
                guard let decoded = decodeKeyMaterial(tweakStr) else {
                    throw KeychainError.providerError("key \(key.ref) tweak: could not decode as hex or base64")
                }
                tweak = decoded
            }
            let status: Status
            if let s = key.status {
                status = Status(rawValue: s) ?? .active
            } else {
                status = .active
            }
            let record = KeyRecord(
                ref: key.ref,
                version: key.version ?? 1,
                status: status,
                algorithm: key.algorithm ?? "",
                material: material,
                tweak: tweak
            )
            records[key.ref, default: []].append(record)
        }
    }

    public func resolve(ref: String) throws -> KeyRecord {
        guard let versions = records[ref] else {
            throw KeychainError.keyNotFound(ref)
        }
        for record in versions.reversed() {
            if record.status == .active {
                return record
            }
        }
        throw KeychainError.noActiveKey(ref)
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        guard let versions = records[ref] else {
            throw KeychainError.keyNotFound(ref)
        }
        for record in versions {
            if record.version == version {
                if record.status == .disabled {
                    throw KeychainError.keyDisabled("\(ref) v\(version)")
                }
                return record
            }
        }
        throw KeychainError.keyNotFound("\(ref) v\(version)")
    }
}

// MARK: - File format

private struct FileKey: Decodable {
    let ref: String
    let version: Int?
    let status: String?
    let algorithm: String?
    let material: String
    let tweak: String?
}

private struct FileConfig: Decodable {
    let keys: [FileKey]
}

/// Attempts to decode a string as hex first, then base64.
private func decodeKeyMaterial(_ s: String) -> Data? {
    let trimmed = s.trimmingCharacters(in: .whitespaces)
    if let data = hexDecode(trimmed) {
        return data
    }
    if let data = Data(base64Encoded: trimmed) {
        return data
    }
    return nil
}
