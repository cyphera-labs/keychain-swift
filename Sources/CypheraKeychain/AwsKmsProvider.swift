// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Resolves keys using AWS KMS GenerateDataKey.
/// Requires: aws-sdk-swift (not yet wired).
public final class AwsKmsProvider: KeyProvider {
    private let keyID: String
    private let region: String
    private let endpoint: String

    /// Creates an AWS KMS key provider.
    public init(keyID: String, region: String, endpoint: String = "") {
        self.keyID = keyID
        self.region = region
        self.endpoint = endpoint
    }

    public func resolve(ref: String) throws -> KeyRecord {
        throw KeychainError.providerError(
            "AWS KMS provider not yet implemented — install aws-sdk-swift and wire GenerateDataKey"
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        return try resolve(ref: ref)
    }
}
