// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Resolves keys from HashiCorp Vault KV v2 secrets.
public final class VaultProvider: KeyProvider {
    private let address: String
    private let token: String
    private let mount: String
    private let session: URLSession

    /// Creates a Vault key provider.
    /// - Parameters:
    ///   - address: Vault server address (e.g. "http://127.0.0.1:8200").
    ///   - token: Vault authentication token.
    ///   - mount: KV v2 mount path (default: "secret").
    public init(address: String, token: String, mount: String = "secret") {
        self.address = address
        self.token = token
        self.mount = mount

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        self.session = URLSession(configuration: config)
    }

    public func resolve(ref: String) throws -> KeyRecord {
        let urlString = "\(address)/v1/\(mount)/data/\(ref)"
        guard let url = URL(string: urlString) else {
            throw KeychainError.providerError("invalid vault URL: \(urlString)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue(token, forHTTPHeaderField: "X-Vault-Token")

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
            throw KeychainError.providerError("vault request failed: \(error.localizedDescription)")
        }
        guard let statusCode = httpResponse?.statusCode else {
            throw KeychainError.providerError("vault returned no response")
        }
        if statusCode == 404 {
            throw KeychainError.keyNotFound(ref)
        }
        if statusCode != 200 {
            let body = responseData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            throw KeychainError.providerError("vault returned \(statusCode): \(body)")
        }
        guard let data = responseData else {
            throw KeychainError.providerError("vault returned empty response")
        }

        let result: VaultResponse
        do {
            result = try JSONDecoder().decode(VaultResponse.self, from: data)
        } catch {
            throw KeychainError.providerError("failed to decode vault response: \(error)")
        }

        guard let materialStr = result.data.data["material"] else {
            throw KeychainError.providerError("vault secret \(ref) missing 'material' field")
        }
        guard let material = hexDecode(materialStr) else {
            throw KeychainError.providerError("invalid hex material in vault secret \(ref)")
        }

        let version: Int
        if let v = result.data.data["version"], let parsed = Int(v) {
            version = parsed
        } else {
            version = 1
        }

        let status: Status
        if let s = result.data.data["status"] {
            status = Status(rawValue: s) ?? .active
        } else {
            status = .active
        }

        let algorithm = result.data.data["algorithm"] ?? ""

        var tweak: Data?
        if let t = result.data.data["tweak"], !t.isEmpty {
            tweak = hexDecode(t)
        }

        return KeyRecord(
            ref: ref,
            version: version,
            status: status,
            algorithm: algorithm,
            material: material,
            tweak: tweak
        )
    }

    public func resolveVersion(ref: String, version: Int) throws -> KeyRecord {
        // Vault KV v2 supports versions via ?version= query param
        // For now, delegate to resolve (returns latest)
        return try resolve(ref: ref)
    }
}

// MARK: - Vault JSON response

private struct VaultResponse: Decodable {
    let data: VaultData
}

private struct VaultData: Decodable {
    let data: [String: String]
}
