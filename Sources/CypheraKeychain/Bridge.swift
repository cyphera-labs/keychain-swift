// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Bridge function called by the Cyphera SDK when cyphera.json has "source"
/// set to a cloud provider. Returns raw key bytes.
public func resolve(source: String, config: [String: String]) throws -> Data {
    let ref = firstNonEmpty(
        config["ref"], config["path"], config["arn"], config["key"], "default"
    )

    let provider = try createProvider(source: source, config: config)

    let record: KeyRecord
    do {
        record = try provider.resolve(ref: ref)
    } catch {
        throw KeychainError.providerError("keychain resolution failed for source '\(source)': \(error)")
    }
    return record.material
}

// MARK: - Internal

private func createProvider(source: String, config: [String: String]) throws -> KeyProvider {
    switch source {
    case "vault":
        let addr = firstNonEmpty(
            config["addr"],
            ProcessInfo.processInfo.environment["VAULT_ADDR"],
            "http://127.0.0.1:8200"
        )
        let token = firstNonEmpty(
            config["token"],
            ProcessInfo.processInfo.environment["VAULT_TOKEN"]
        )
        let mount = firstNonEmpty(config["mount"], "secret")
        return VaultProvider(address: addr, token: token, mount: mount)

    case "aws-kms":
        let arn = config["arn"] ?? ""
        let region = firstNonEmpty(
            config["region"],
            ProcessInfo.processInfo.environment["AWS_REGION"],
            "us-east-1"
        )
        let endpoint = config["endpoint"] ?? ""
        return AwsKmsProvider(keyID: arn, region: region, endpoint: endpoint)

    case "gcp-kms":
        let resource = config["resource"] ?? ""
        return GcpKmsProvider(keyName: resource)

    case "azure-kv":
        let vault = config["vault"] ?? ""
        let vaultURL = "https://\(vault).vault.azure.net"
        let key = config["key"] ?? ""
        return AzureKvProvider(vaultURL: vaultURL, keyName: key)

    default:
        throw KeychainError.providerError("unknown source: \(source)")
    }
}

private func firstNonEmpty(_ values: String?...) -> String {
    for value in values {
        if let v = value, !v.isEmpty {
            return v
        }
    }
    return ""
}
