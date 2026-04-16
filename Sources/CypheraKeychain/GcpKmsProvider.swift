// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Resolves keys using GCP Cloud KMS via REST API.
///
/// Uses the Cloud KMS REST API to generate random key material and optionally
/// encrypt/decrypt it with a Cloud KMS key. Connects to the configured
/// endpoint, which can be overridden for emulator or mock testing.
///
/// Authentication uses a Bearer token. Supply `accessToken` directly, or
/// leave it empty to read from the `GOOGLE_ACCESS_TOKEN` environment variable.
/// For production, obtain tokens via `gcloud auth print-access-token` or
/// a service account credential flow.
///
/// **Note:** OAuth2 / service-account token refresh is not yet implemented.
/// Provide a pre-fetched access token for now.
public final class GcpKmsProvider: KeyProvider {
    private let keyName: String
    private let endpoint: String
    private let accessToken: String
    private let session: URLSession

    /// Creates a GCP Cloud KMS key provider.
    /// - Parameters:
    ///   - keyName: Full resource name of the CryptoKey, e.g.
    ///     "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key".
    ///   - endpoint: Custom API endpoint. Defaults to the public Cloud KMS API.
    ///   - accessToken: OAuth2 bearer token. Falls back to `GOOGLE_ACCESS_TOKEN` env var.
    public init(
        keyName: String,
        endpoint: String = "https://cloudkms.googleapis.com",
        accessToken: String = ""
    ) {
        self.keyName = keyName
        self.endpoint = endpoint
        self.accessToken = accessToken.isEmpty
            ? ProcessInfo.processInfo.environment["GOOGLE_ACCESS_TOKEN"] ?? ""
            : accessToken

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        self.session = URLSession(configuration: config)
    }

    /// Returns a `MemoryProvider` pre-loaded with the given material,
    /// useful for testing without a live Cloud KMS endpoint.
    public static func withMaterial(ref: String, material: Data) -> MemoryProvider {
        return MemoryProvider(records: [
            KeyRecord(
                ref: ref,
                version: 1,
                status: .active,
                algorithm: "AES-256",
                material: material,
                metadata: ["source": "gcp-kms-test"]
            )
        ])
    }

    public func resolve(ref: String) throws -> KeyRecord {
        // Step 1: Generate random bytes via Cloud KMS generateRandomBytes
        let material = try generateRandomBytes(lengthBytes: 32)

        // Step 2: Encrypt the material with the Cloud KMS key so we can store
        // the ciphertext alongside the plaintext ref.
        let ciphertext = try encrypt(plaintext: material, context: ref)

        return KeyRecord(
            ref: ref,
            version: 1,
            status: .active,
            algorithm: "AES-256",
            material: material,
            metadata: [
                "source": "gcp-kms",
                "keyName": keyName,
                "ciphertext": ciphertext.base64EncodedString()
            ]
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        // Cloud KMS key versions are managed server-side;
        // versioning is handled externally.
        return try resolve(ref: ref)
    }

    // MARK: - Cloud KMS REST calls

    /// Generates random bytes using the Cloud KMS generateRandomBytes API.
    private func generateRandomBytes(lengthBytes: Int) throws -> Data {
        // Extract location from keyName for the generateRandomBytes endpoint.
        // keyName format: projects/{project}/locations/{location}/keyRings/...
        let location = extractLocation(from: keyName) ?? "global"
        let project = extractProject(from: keyName) ?? "-"
        let urlString = "\(endpoint)/v1/projects/\(project)/locations/\(location):generateRandomBytes"
        guard let url = URL(string: urlString) else {
            throw KeychainError.providerError("invalid GCP KMS URL: \(urlString)")
        }

        let body = GenerateRandomBytesRequest(lengthBytes: lengthBytes, protectionLevel: "HSM")
        let bodyData = try JSONEncoder().encode(body)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        let (data, statusCode) = try performRequest(request)

        if statusCode != 200 {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw KeychainError.providerError("GCP KMS generateRandomBytes returned \(statusCode): \(body)")
        }

        let result: GenerateRandomBytesResponse
        do {
            result = try JSONDecoder().decode(GenerateRandomBytesResponse.self, from: data)
        } catch {
            throw KeychainError.providerError("failed to decode GCP KMS generateRandomBytes response: \(error)")
        }

        guard let decoded = Data(base64Encoded: result.data) else {
            throw KeychainError.providerError("invalid base64 in GCP KMS generateRandomBytes response")
        }
        return decoded
    }

    /// Encrypts plaintext with the Cloud KMS key.
    private func encrypt(plaintext: Data, context: String) throws -> Data {
        let urlString = "\(endpoint)/v1/\(keyName):encrypt"
        guard let url = URL(string: urlString) else {
            throw KeychainError.providerError("invalid GCP KMS URL: \(urlString)")
        }

        let body = EncryptRequest(
            plaintext: plaintext.base64EncodedString(),
            additionalAuthenticatedData: Data(context.utf8).base64EncodedString()
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
            throw KeychainError.providerError("GCP KMS encrypt returned \(statusCode): \(respBody)")
        }

        let result: EncryptResponse
        do {
            result = try JSONDecoder().decode(EncryptResponse.self, from: data)
        } catch {
            throw KeychainError.providerError("failed to decode GCP KMS encrypt response: \(error)")
        }

        guard let ciphertext = Data(base64Encoded: result.ciphertext) else {
            throw KeychainError.providerError("invalid base64 ciphertext in GCP KMS encrypt response")
        }
        return ciphertext
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
            throw KeychainError.providerError("GCP KMS request failed: \(error.localizedDescription)")
        }
        guard let statusCode = httpResponse?.statusCode else {
            throw KeychainError.providerError("GCP KMS returned no response")
        }
        guard let data = responseData else {
            throw KeychainError.providerError("GCP KMS returned empty response")
        }
        return (data, statusCode)
    }

    private func extractProject(from keyName: String) -> String? {
        let parts = keyName.split(separator: "/")
        guard let idx = parts.firstIndex(of: "projects"), idx + 1 < parts.count else {
            return nil
        }
        return String(parts[idx + 1])
    }

    private func extractLocation(from keyName: String) -> String? {
        let parts = keyName.split(separator: "/")
        guard let idx = parts.firstIndex(of: "locations"), idx + 1 < parts.count else {
            return nil
        }
        return String(parts[idx + 1])
    }
}

// MARK: - GCP KMS JSON request/response types

private struct GenerateRandomBytesRequest: Encodable {
    let lengthBytes: Int
    let protectionLevel: String
}

private struct GenerateRandomBytesResponse: Decodable {
    let data: String
}

private struct EncryptRequest: Encodable {
    let plaintext: String
    let additionalAuthenticatedData: String
}

private struct EncryptResponse: Decodable {
    let name: String?
    let ciphertext: String
}
