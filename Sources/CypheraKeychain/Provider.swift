// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Lifecycle state of a key version.
public enum Status: String, Codable, Sendable {
    case active
    case deprecated
    case disabled
}

/// Resolved key material and metadata.
public struct KeyRecord: Sendable {
    public let ref: String
    public let version: Int
    public let status: Status
    public let algorithm: String
    public let material: Data
    public let tweak: Data?
    public let metadata: [String: String]
    public let createdAt: Date

    public init(
        ref: String,
        version: Int = 1,
        status: Status = .active,
        algorithm: String = "",
        material: Data,
        tweak: Data? = nil,
        metadata: [String: String] = [:],
        createdAt: Date = Date()
    ) {
        self.ref = ref
        self.version = version
        self.status = status
        self.algorithm = algorithm
        self.material = material
        self.tweak = tweak
        self.metadata = metadata
        self.createdAt = createdAt
    }
}

/// Errors returned by key providers.
public enum KeychainError: Error, Equatable {
    case keyNotFound(String)
    case keyDisabled(String)
    case noActiveKey(String)
    case providerError(String)
}

/// Resolves key references to key material.
public protocol KeyProvider {
    func resolve(ref: String) throws -> KeyRecord
    func resolveVersion(ref: String, version: Int) throws -> KeyRecord
}
