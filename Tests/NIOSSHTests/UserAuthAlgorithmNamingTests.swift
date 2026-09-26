//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation
import NIOCore
@testable import NIOSSH
import XCTest

/// A key of type "custom-prefix" that signs with "custom-prefix-sha2", like an
/// "ssh-rsa" key signing with "rsa-sha2-512" (RFC 8332).
private struct NamedPublicKey: NIOSSHPublicKeyProtocol, NIOSSHUserAuthAlgorithmNaming {
    static let publicKeyPrefix = CustomPublicKey.publicKeyPrefix
    var userAuthAlgorithm: String { "custom-prefix-sha2" }

    var rawRepresentation: Data { CustomPublicKey().rawRepresentation }

    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        CustomPublicKey().isValidSignature(signature, for: data)
    }

    func write(to buffer: inout ByteBuffer) -> Int { CustomPublicKey().write(to: &buffer) }

    static func read(from buffer: inout ByteBuffer) throws -> NamedPublicKey {
        _ = try CustomPublicKey.read(from: &buffer)
        return NamedPublicKey()
    }
}

private struct NamedPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = CustomPrivateKey.keyPrefix
    var publicKey: NIOSSHPublicKeyProtocol { NamedPublicKey() }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        try CustomPrivateKey().signature(for: data)
    }
}

final class UserAuthAlgorithmNamingTests: XCTestCase {
    private let sessionID = ByteBuffer(bytes: [1, 2, 3, 4])

    func testRequestNamesTheAlgorithmButKeepsTheKeyType() throws {
        let key = NIOSSHPrivateKey(custom: NamedPrivateKey())
        let offer = NIOSSHUserAuthenticationOffer(
            username: "user", serviceName: "", offer: .privateKey(.init(privateKey: key)))
        let message = try SSHMessage.UserAuthRequestMessage(request: offer, sessionID: self.sessionID)

        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHMessage(.userAuthRequest(message))

        XCTAssertEqual(buffer.readInteger(as: UInt8.self), SSHMessage.UserAuthRequestMessage.id)
        XCTAssertEqual(buffer.readSSHStringAsString(), "user")
        XCTAssertEqual(buffer.readSSHStringAsString(), "ssh-connection")
        XCTAssertEqual(buffer.readSSHStringAsString(), "publickey")
        XCTAssertEqual(buffer.readSSHBoolean(), true)
        XCTAssertEqual(buffer.readSSHStringAsString(), "custom-prefix-sha2")
        var blob = try XCTUnwrap(buffer.readSSHString())
        XCTAssertEqual(blob.readSSHStringAsString(), "custom-prefix")
    }

    func testSignedPayloadNamesTheAlgorithm() {
        let key = NIOSSHPrivateKey(custom: NamedPrivateKey())
        let payload = UserAuthSignablePayload(
            sessionIdentifier: self.sessionID, userName: "user", serviceName: "ssh-connection", publicKey: key.publicKey)

        var bytes = payload.bytes
        _ = bytes.readSSHString()  // session identifier
        XCTAssertEqual(bytes.readInteger(as: UInt8.self), SSHMessage.UserAuthRequestMessage.id)
        XCTAssertEqual(bytes.readSSHStringAsString(), "user")
        XCTAssertEqual(bytes.readSSHStringAsString(), "ssh-connection")
        XCTAssertEqual(bytes.readSSHStringAsString(), "publickey")
        XCTAssertEqual(bytes.readSSHBoolean(), true)
        XCTAssertEqual(bytes.readSSHStringAsString(), "custom-prefix-sha2")
    }

    func testKeysWithoutANameUseTheirKeyType() throws {
        let key = NIOSSHPrivateKey(custom: CustomPrivateKey())
        XCTAssertEqual(String(key.publicKey.userAuthAlgorithm), "custom-prefix")

        let ed25519 = NIOSSHPrivateKey(ed25519Key: .init())
        XCTAssertEqual(String(ed25519.publicKey.userAuthAlgorithm), "ssh-ed25519")
    }
}
