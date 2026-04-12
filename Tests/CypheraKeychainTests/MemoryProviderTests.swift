// Copyright 2026 Horizon Digital Engineering LLC
// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import CypheraKeychain

final class MemoryProviderTests: XCTestCase {

    func testResolveReturnsActiveKey() throws {
        let material = Data([0x00, 0x11, 0x22, 0x33])
        let provider = MemoryProvider(records: [
            KeyRecord(ref: "test-key", version: 1, status: .active, material: material)
        ])

        let record = try provider.resolve(ref: "test-key")
        XCTAssertEqual(record.ref, "test-key")
        XCTAssertEqual(record.version, 1)
        XCTAssertEqual(record.status, .active)
        XCTAssertEqual(record.material, material)
    }

    func testResolveReturnsLatestActiveVersion() throws {
        let v1 = Data([0x01])
        let v2 = Data([0x02])
        let provider = MemoryProvider(records: [
            KeyRecord(ref: "key", version: 1, status: .active, material: v1),
            KeyRecord(ref: "key", version: 2, status: .active, material: v2)
        ])

        let record = try provider.resolve(ref: "key")
        XCTAssertEqual(record.version, 2)
        XCTAssertEqual(record.material, v2)
    }

    func testResolveSkipsDeprecatedVersions() throws {
        let v1 = Data([0x01])
        let v2 = Data([0x02])
        let provider = MemoryProvider(records: [
            KeyRecord(ref: "key", version: 1, status: .active, material: v1),
            KeyRecord(ref: "key", version: 2, status: .deprecated, material: v2)
        ])

        let record = try provider.resolve(ref: "key")
        XCTAssertEqual(record.version, 1)
    }

    func testResolveThrowsKeyNotFound() {
        let provider = MemoryProvider(records: [])

        XCTAssertThrowsError(try provider.resolve(ref: "missing")) { error in
            guard case KeychainError.keyNotFound = error else {
                XCTFail("Expected keyNotFound, got \(error)")
                return
            }
        }
    }

    func testResolveThrowsNoActiveKey() {
        let provider = MemoryProvider(records: [
            KeyRecord(ref: "key", version: 1, status: .disabled, material: Data([0x01]))
        ])

        XCTAssertThrowsError(try provider.resolve(ref: "key")) { error in
            guard case KeychainError.noActiveKey = error else {
                XCTFail("Expected noActiveKey, got \(error)")
                return
            }
        }
    }

    func testResolveVersionReturnsSpecificVersion() throws {
        let v1 = Data([0x01])
        let v2 = Data([0x02])
        let provider = MemoryProvider(records: [
            KeyRecord(ref: "key", version: 1, status: .active, material: v1),
            KeyRecord(ref: "key", version: 2, status: .active, material: v2)
        ])

        let record = try provider.resolveVersion(ref: "key", version: 1)
        XCTAssertEqual(record.version, 1)
        XCTAssertEqual(record.material, v1)
    }

    func testResolveVersionThrowsKeyDisabled() {
        let provider = MemoryProvider(records: [
            KeyRecord(ref: "key", version: 1, status: .disabled, material: Data([0x01]))
        ])

        XCTAssertThrowsError(try provider.resolveVersion(ref: "key", version: 1)) { error in
            guard case KeychainError.keyDisabled = error else {
                XCTFail("Expected keyDisabled, got \(error)")
                return
            }
        }
    }

    func testResolveVersionThrowsKeyNotFound() {
        let provider = MemoryProvider(records: [
            KeyRecord(ref: "key", version: 1, status: .active, material: Data([0x01]))
        ])

        XCTAssertThrowsError(try provider.resolveVersion(ref: "key", version: 99)) { error in
            guard case KeychainError.keyNotFound = error else {
                XCTFail("Expected keyNotFound, got \(error)")
                return
            }
        }
    }

    func testStatusEnum() {
        XCTAssertEqual(Status.active.rawValue, "active")
        XCTAssertEqual(Status.deprecated.rawValue, "deprecated")
        XCTAssertEqual(Status.disabled.rawValue, "disabled")
    }

    func testKeyRecordMetadata() throws {
        let provider = MemoryProvider(records: [
            KeyRecord(
                ref: "key",
                version: 1,
                status: .active,
                algorithm: "AES-256-GCM",
                material: Data([0xAA, 0xBB]),
                tweak: Data([0xCC]),
                metadata: ["env": "prod"]
            )
        ])

        let record = try provider.resolve(ref: "key")
        XCTAssertEqual(record.algorithm, "AES-256-GCM")
        XCTAssertEqual(record.tweak, Data([0xCC]))
        XCTAssertEqual(record.metadata["env"], "prod")
    }
}
