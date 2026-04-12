// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Resolves keys using Azure Key Vault.
/// Requires: azure-sdk-for-swift (not yet wired).
public final class AzureKvProvider: KeyProvider {
    private let vaultURL: String
    private let keyName: String

    /// Creates an Azure Key Vault key provider.
    public init(vaultURL: String, keyName: String) {
        self.vaultURL = vaultURL
        self.keyName = keyName
    }

    public func resolve(ref: String) throws -> KeyRecord {
        throw KeychainError.providerError(
            "Azure Key Vault provider not yet implemented — install azure-sdk-for-swift and wire RSA-OAEP wrapping"
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        return try resolve(ref: ref)
    }
}
