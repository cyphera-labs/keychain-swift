// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Security)
import Security
#endif

/// Resolves keys using Azure Key Vault REST API.
///
/// Uses the Key Vault REST API to generate and wrap key material. Connects to
/// the configured vault URL, which can point to a mock or Azurite-based
/// endpoint for testing.
///
/// Authentication uses a Bearer token (Azure AD / Entra ID). Supply
/// `accessToken` directly, or leave it empty to read from the
/// `AZURE_ACCESS_TOKEN` environment variable. For production, obtain tokens
/// via `az account get-access-token --resource https://vault.azure.net` or
/// the MSAL library.
///
/// **Note:** Azure AD token acquisition is not yet built in. Provide a
/// pre-fetched access token for now.
public final class AzureKvProvider: KeyProvider {
    private let vaultURL: String
    private let keyName: String
    private let apiVersion: String
    private let accessToken: String
    private let session: URLSession

    /// Creates an Azure Key Vault key provider.
    /// - Parameters:
    ///   - vaultURL: Vault base URL (e.g. "https://my-vault.vault.azure.net").
    ///   - keyName: Name of the Key Vault key used for wrapping/unwrapping.
    ///   - apiVersion: Key Vault REST API version (default: "7.4").
    ///   - accessToken: Azure AD bearer token. Falls back to `AZURE_ACCESS_TOKEN` env var.
    public init(
        vaultURL: String,
        keyName: String,
        apiVersion: String = "7.4",
        accessToken: String = ""
    ) {
        self.vaultURL = vaultURL.hasSuffix("/") ? String(vaultURL.dropLast()) : vaultURL
        self.keyName = keyName
        self.apiVersion = apiVersion
        self.accessToken = accessToken.isEmpty
            ? ProcessInfo.processInfo.environment["AZURE_ACCESS_TOKEN"] ?? ""
            : accessToken

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        self.session = URLSession(configuration: config)
    }

    /// Returns a `MemoryProvider` pre-loaded with the given material,
    /// useful for testing without a live Key Vault endpoint.
    public static func withMaterial(ref: String, material: Data) -> MemoryProvider {
        return MemoryProvider(records: [
            KeyRecord(
                ref: ref,
                version: 1,
                status: .active,
                algorithm: "AES-256",
                material: material,
                metadata: ["source": "azure-kv-test"]
            )
        ])
    }

    public func resolve(ref: String) throws -> KeyRecord {
        // Step 1: Get the wrapping key info to confirm it exists
        let keyInfo = try getKey()

        // Step 2: Generate random material locally and wrap it with the
        // Key Vault key using RSA-OAEP wrapKey operation.
        let material = try generateRandomMaterial(count: 32)

        let wrappedKey = try wrapKey(plaintext: material)

        return KeyRecord(
            ref: ref,
            version: 1,
            status: .active,
            algorithm: "AES-256",
            material: material,
            metadata: [
                "source": "azure-kv",
                "keyName": keyName,
                "kid": keyInfo.kid,
                "wrappedKey": wrappedKey.base64EncodedString()
            ]
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        // Key Vault key versions are managed server-side;
        // versioning is handled externally.
        return try resolve(ref: ref)
    }

    // MARK: - Key Vault REST calls

    /// Retrieves key metadata via GET /keys/{keyName}.
    private func getKey() throws -> KeyInfo {
        let urlString = "\(vaultURL)/keys/\(keyName)?api-version=\(apiVersion)"
        guard let url = URL(string: urlString) else {
            throw KeychainError.providerError("invalid Azure Key Vault URL: \(urlString)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        let (data, statusCode) = try performRequest(request)

        if statusCode == 404 {
            throw KeychainError.keyNotFound(keyName)
        }
        if statusCode != 200 {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw KeychainError.providerError("Azure Key Vault getKey returned \(statusCode): \(body)")
        }

        let result: GetKeyResponse
        do {
            result = try JSONDecoder().decode(GetKeyResponse.self, from: data)
        } catch {
            throw KeychainError.providerError("failed to decode Azure Key Vault getKey response: \(error)")
        }

        return KeyInfo(kid: result.key.kid)
    }

    /// Wraps plaintext using POST /keys/{keyName}/wrapkey with RSA-OAEP.
    private func wrapKey(plaintext: Data) throws -> Data {
        let urlString = "\(vaultURL)/keys/\(keyName)/wrapkey?api-version=\(apiVersion)"
        guard let url = URL(string: urlString) else {
            throw KeychainError.providerError("invalid Azure Key Vault URL: \(urlString)")
        }

        let body = WrapKeyRequest(
            alg: "RSA-OAEP",
            value: base64URLEncode(plaintext)
        )
        let bodyData = try JSONEncoder().encode(body)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        let (data, statusCode) = try performRequest(request)

        if statusCode != 200 {
            let respBody = String(data: data, encoding: .utf8) ?? ""
            throw KeychainError.providerError("Azure Key Vault wrapKey returned \(statusCode): \(respBody)")
        }

        let result: WrapKeyResponse
        do {
            result = try JSONDecoder().decode(WrapKeyResponse.self, from: data)
        } catch {
            throw KeychainError.providerError("failed to decode Azure Key Vault wrapKey response: \(error)")
        }

        guard let wrapped = base64URLDecode(result.value) else {
            throw KeychainError.providerError("invalid base64url in Azure Key Vault wrapKey response")
        }
        return wrapped
    }

    // MARK: - Helpers

    private func performRequest(_ request: URLRequest) throws -> (Data, Int) {
        var responseData: Data?
        var responseError: Error?
        var httpResponse: HTTPURLResponse?

        let semaphore = DispatchSemaphore(value: 0)
        let task = session.dataTask(with: request) { data, response, error in
            responseData = data
            responseError = error
            httpResponse = response as? HTTPURLResponse
            semaphore.signal()
        }
        task.resume()
        semaphore.wait()

        if let error = responseError {
            throw KeychainError.providerError("Azure Key Vault request failed: \(error.localizedDescription)")
        }
        guard let statusCode = httpResponse?.statusCode else {
            throw KeychainError.providerError("Azure Key Vault returned no response")
        }
        guard let data = responseData else {
            throw KeychainError.providerError("Azure Key Vault returned empty response")
        }
        return (data, statusCode)
    }

    /// Generates cryptographically secure random bytes (cross-platform).
    private func generateRandomMaterial(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        #if canImport(Security)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw KeychainError.providerError("failed to generate random key material")
        }
        #else
        // Linux: read from /dev/urandom
        guard let fh = FileHandle(forReadingAtPath: "/dev/urandom") else {
            throw KeychainError.providerError("failed to open /dev/urandom")
        }
        let data = fh.readData(ofLength: count)
        fh.closeFile()
        guard data.count == count else {
            throw KeychainError.providerError("failed to read enough random bytes")
        }
        bytes = Array(data)
        #endif
        return Data(bytes)
    }

    /// Encodes Data to base64url (no padding) as required by Azure Key Vault.
    private func base64URLEncode(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes a base64url string (no padding) to Data.
    private func base64URLDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }
}

// MARK: - Azure Key Vault JSON types

private struct KeyInfo {
    let kid: String
}

private struct GetKeyResponse: Decodable {
    let key: GetKeyResponseKey
}

private struct GetKeyResponseKey: Decodable {
    let kid: String
    let kty: String?
}

private struct WrapKeyRequest: Encodable {
    let alg: String
    let value: String
}

private struct WrapKeyResponse: Decodable {
    let kid: String?
    let value: String
}
