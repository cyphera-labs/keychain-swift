// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Stores keys in memory. For dev/test only.
public final class MemoryProvider: KeyProvider {
    private var records: [String: [KeyRecord]] = [:]

    /// Creates a provider from a list of key records.
    public init(records: [KeyRecord]) {
        for record in records {
            self.records[record.ref, default: []].append(record)
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
