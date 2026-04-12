// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Resolves keys using GCP Cloud KMS.
/// Requires: googleapis-swift (not yet wired).
public final class GcpKmsProvider: KeyProvider {
    private let keyName: String

    /// Creates a GCP Cloud KMS key provider.
    public init(keyName: String) {
        self.keyName = keyName
    }

    public func resolve(ref: String) throws -> KeyRecord {
        throw KeychainError.providerError(
            "GCP KMS provider not yet implemented — install googleapis-swift and wire encrypt/decrypt"
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        return try resolve(ref: ref)
    }
}
