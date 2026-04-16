// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Resolves keys using AWS KMS GenerateDataKey via REST API.
///
/// Uses the AWS KMS JSON API over HTTP. Connects to the configured endpoint,
/// which can point to LocalStack or another KMS-compatible service for testing.
///
/// Authentication uses AWS Signature Version 4. Supply credentials via
/// `accessKeyId` and `secretAccessKey`, or leave them empty to rely on
/// environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
///
/// **Note:** SigV4 request signing is not yet implemented. For production use,
/// integrate `aws-sdk-swift` or add a SigV4 signer. The HTTP request structure
/// and JSON parsing are fully functional for use with LocalStack (which does
/// not enforce signatures).
public final class AwsKmsProvider: KeyProvider {
    private let keyID: String
    private let region: String
    private let endpoint: String
    private let accessKeyId: String
    private let secretAccessKey: String
    private let session: URLSession

    /// Creates an AWS KMS key provider.
    /// - Parameters:
    ///   - keyID: The KMS key ID or ARN used with GenerateDataKey.
    ///   - region: AWS region (e.g. "us-east-1").
    ///   - endpoint: Custom endpoint URL (e.g. "http://localhost:4566" for LocalStack).
    ///               When empty, defaults to the standard KMS endpoint for the region.
    ///   - accessKeyId: AWS access key. Falls back to `AWS_ACCESS_KEY_ID` env var.
    ///   - secretAccessKey: AWS secret key. Falls back to `AWS_SECRET_ACCESS_KEY` env var.
    public init(
        keyID: String,
        region: String,
        endpoint: String = "",
        accessKeyId: String = "",
        secretAccessKey: String = ""
    ) {
        self.keyID = keyID
        self.region = region
        self.endpoint = endpoint.isEmpty
            ? "https://kms.\(region).amazonaws.com"
            : endpoint
        self.accessKeyId = accessKeyId.isEmpty
            ? ProcessInfo.processInfo.environment["AWS_ACCESS_KEY_ID"] ?? ""
            : accessKeyId
        self.secretAccessKey = secretAccessKey.isEmpty
            ? ProcessInfo.processInfo.environment["AWS_SECRET_ACCESS_KEY"] ?? ""
            : secretAccessKey

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        self.session = URLSession(configuration: config)
    }

    /// Returns a `MemoryProvider` pre-loaded with the given material,
    /// useful for testing without a live KMS endpoint.
    public static func withMaterial(ref: String, material: Data) -> MemoryProvider {
        return MemoryProvider(records: [
            KeyRecord(
                ref: ref,
                version: 1,
                status: .active,
                algorithm: "AES-256",
                material: material,
                metadata: ["source": "aws-kms-test"]
            )
        ])
    }

    public func resolve(ref: String) throws -> KeyRecord {
        let body = GenerateDataKeyRequest(
            KeyId: keyID,
            KeySpec: "AES_256",
            EncryptionContext: ["ref": ref]
        )
        let bodyData = try JSONEncoder().encode(body)

        guard let url = URL(string: endpoint) else {
            throw KeychainError.providerError("invalid AWS KMS endpoint: \(endpoint)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        request.setValue("application/x-amz-json-1.1", forHTTPHeaderField: "Content-Type")
        request.setValue("TrentService.GenerateDataKey", forHTTPHeaderField: "X-Amz-Target")
        request.setValue(hostHeader(from: endpoint), forHTTPHeaderField: "Host")

        // TODO: Add AWS SigV4 signing here. For LocalStack testing, signatures
        // are not enforced and requests work without signing.

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
            throw KeychainError.providerError("AWS KMS request failed: \(error.localizedDescription)")
        }
        guard let statusCode = httpResponse?.statusCode else {
            throw KeychainError.providerError("AWS KMS returned no response")
        }
        if statusCode == 404 {
            throw KeychainError.keyNotFound(ref)
        }
        if statusCode != 200 {
            let body = responseData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            throw KeychainError.providerError("AWS KMS returned \(statusCode): \(body)")
        }
        guard let data = responseData else {
            throw KeychainError.providerError("AWS KMS returned empty response")
        }

        let result: GenerateDataKeyResponse
        do {
            result = try JSONDecoder().decode(GenerateDataKeyResponse.self, from: data)
        } catch {
            throw KeychainError.providerError("failed to decode AWS KMS response: \(error)")
        }

        guard let material = Data(base64Encoded: result.Plaintext) else {
            throw KeychainError.providerError("invalid base64 plaintext in AWS KMS response")
        }

        return KeyRecord(
            ref: ref,
            version: 1,
            status: .active,
            algorithm: "AES-256",
            material: material,
            metadata: [
                "source": "aws-kms",
                "keyId": result.KeyId,
                "ciphertextBlob": result.CiphertextBlob
            ]
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        // AWS KMS GenerateDataKey produces new material each call;
        // versioning is managed externally.
        return try resolve(ref: ref)
    }

    private func hostHeader(from endpoint: String) -> String {
        if let url = URL(string: endpoint), let host = url.host {
            if let port = url.port, port != 443, port != 80 {
                return "\(host):\(port)"
            }
            return host
        }
        return endpoint
    }
}

// MARK: - AWS KMS JSON request/response

private struct GenerateDataKeyRequest: Encodable {
    let KeyId: String
    let KeySpec: String
    let EncryptionContext: [String: String]
}

private struct GenerateDataKeyResponse: Decodable {
    let CiphertextBlob: String
    let KeyId: String
    let Plaintext: String
}
