import CryptoKit
import Darwin
import Foundation
import MopCore
import Security
import SwiftASN1
import X509

public struct CertificateSubject: Sendable {
    public var commonName: String
    public var organization: String?
    public var organizationalUnit: String?
    public var country: String?
    public init(commonName: String, organization: String? = nil, organizationalUnit: String? = nil, country: String? = nil) {
        self.commonName = commonName; self.organization = organization; self.organizationalUnit = organizationalUnit; self.country = country
    }
}
public enum CertificateAlternativeName: Sendable { case dns(String), email(String), uri(String), ip(String) }
public struct LocalCertificateInfo: Encodable, Sendable {
    public let subject: String
    public let issuer: String
    public let validFrom: Date
    public let validUntil: Date
    public let extensions: String
    public let expired: Bool
    public let trustValidated = false
}

/// DER construction is delegated to SwiftASN1, including lengths and tagging.
private indirect enum DERNode: DERSerializable {
    case primitive(ASN1Identifier, [UInt8])
    case constructed(ASN1Identifier, [DERNode])
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .primitive(let tag, let bytes): coder.appendPrimitiveNode(identifier: tag) { $0.append(contentsOf: bytes) }
        case .constructed(let tag, let children): try coder.appendConstructedNode(identifier: tag) { coder in for child in children { try coder.serialize(child) } }
        }
    }
    static func sequence(_ nodes: [Self]) -> Self { .constructed(.sequence, nodes) }
    static func oid(_ bytes: [UInt8]) -> Self { .primitive(.objectIdentifier, bytes) }
    func bytes() throws -> Data { try derBytes(self) }
}
public enum LocalCSR {
    public static func requestInfo(publicKey: Data, subject: CertificateSubject, names: [CertificateAlternativeName]) throws -> Data {
        _ = try P256.Signing.PublicKey(x963Representation: publicKey)
        guard !subject.commonName.isEmpty, names.count <= 128 else { throw MopError.invalidLocalIdentity }
        var rdns: [DERNode] = []
        for (number, value) in [(UInt8(3), Optional(subject.commonName)), (10, subject.organization), (11, subject.organizationalUnit), (6, subject.country)] {
            guard let value else { continue }
            guard !value.isEmpty, value.utf8.count <= 256, !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { throw MopError.invalidLocalIdentity }
            if number == 6 { guard value.utf8.count == 2, value.utf8.allSatisfy({ (65...90).contains($0) }) else { throw MopError.invalidLocalIdentity } }
            rdns.append(.constructed(.set, [.sequence([.oid([0x55, 0x04, number]), .primitive(number == 6 ? .printableString : .utf8String, Array(value.utf8))])]))
        }
        let spki = DERNode.sequence([.sequence([.oid([0x2a,0x86,0x48,0xce,0x3d,0x02,0x01]), .oid([0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07])]), .primitive(.bitString, [0] + publicKey)])
        var attributes: [DERNode] = []
        if !names.isEmpty {
            let generalNames = try names.map { name -> DERNode in
                let tag: UInt, bytes: [UInt8]
                switch name {
                case .dns(let value): tag = 2; bytes = Array(value.utf8)
                case .email(let value): tag = 1; bytes = Array(value.utf8)
                case .uri(let value): tag = 6; bytes = Array(value.utf8)
                case .ip(let value):
                    tag = 7
                    var ipv4 = in_addr(), ipv6 = in6_addr()
                    if inet_pton(AF_INET, value, &ipv4) == 1 { bytes = withUnsafeBytes(of: ipv4) { Array($0) } }
                    else if inet_pton(AF_INET6, value, &ipv6) == 1 { bytes = withUnsafeBytes(of: ipv6) { Array($0) } }
                    else { throw MopError.invalidLocalIdentity }
                }
                guard !bytes.isEmpty, bytes.count <= 2048, tag == 7 || bytes.allSatisfy({ $0 >= 0x21 && $0 < 0x7f }) else { throw MopError.invalidLocalIdentity }
                return .primitive(ASN1Identifier(tagWithNumber: tag, tagClass: .contextSpecific), bytes)
            }
            let san = DERNode.sequence([.oid([0x55,0x1d,0x11]), .primitive(.octetString, Array(try DERNode.sequence(generalNames).bytes()))])
            attributes = [.sequence([.oid([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x0e]), .constructed(.set, [.sequence([san])])])]
        }
        return try DERNode.sequence([.primitive(.integer, [0]), .sequence(rdns), spki, .constructed(ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific), attributes)]).bytes()
    }
    public static func pem(requestInfo: Data, signature: Data) throws -> String {
        // Parse the request before embedding it; do not accept arbitrary DER fragments.
        let info = try ASN1Any(derEncoded: DER.parse(Array(requestInfo)))
        var coder = DER.Serializer()
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(info)
            try coder.serialize(DERNode.sequence([.oid([0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02])]))
            try coder.serialize(DERNode.primitive(.bitString, [0] + signature))
        }
        return PEMDocument(type: "CERTIFICATE REQUEST", derBytes: coder.serializedBytes).pemString
    }
}
extension LocalIdentityStore {
    public func csr(id: UUID, subject: CertificateSubject, names: [CertificateAlternativeName], authorization: LocalAuthorization) throws -> String {
        let identity = try read(id: id)
        guard identity.protocolType == .x509 else { throw MopError.localIdentityCapability }
        let info = try LocalCSR.requestInfo(publicKey: identity.publicKey, subject: subject, names: names)
        let pem = try LocalCSR.pem(requestInfo: info, signature: sign(id: id, data: info, authorization: authorization, operation: .csr))
        try authorization.check(); return pem
    }
    public func attachCertificates(id: UUID, data: Data, authorization: LocalAuthorization) throws {
        guard data.count <= 4 * 1024 * 1024 else { throw MopError.invalidLocalIdentity }
        let record = try fetch(id)
        guard record.identity.protocolType == .x509 else { throw MopError.localIdentityCapability }
        let chain = try Self.parseCertificates(data)
        guard let first = chain.first, let key = P256.Signing.PublicKey(first.publicKey), key.x963Representation == record.identity.publicKey else { throw MopError.invalidLocalIdentity }
        let old = record.identity
        let identity = try LocalIdentity(id: old.id, name: old.name, algorithm: old.algorithm, protocolType: old.protocolType, publicKey: old.publicKey, createdAt: old.createdAt, accessPolicy: old.accessPolicy, metadata: .certificate(chain: try chain.map { try derBytes($0) }))
        try authorization.begin(id: id, purpose: .x509, operation: .certificate)
        try authorization.check()
        var query = baseQuery(); query[kSecAttrAccount as String] = id.uuidString
        try Self.check(SecItemUpdate(query as CFDictionary, [kSecValueData as String: try Self.encode(Record(version: 2, identity: identity, opaqueKey: record.opaqueKey))] as CFDictionary))
        try authorization.check()
    }
    static func parseCertificates(_ data: Data) throws -> [Certificate] {
        let chain: [Certificate]
        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN") {
            let documents = try PEMDocument.parseMultiple(pemString: text)
            guard documents.allSatisfy({ $0.discriminator == "CERTIFICATE" }) else { throw MopError.invalidLocalIdentity }
            chain = try documents.map { try Certificate(derEncoded: $0.derBytes) }
        } else { chain = [try Certificate(derEncoded: Array(data))] }
        guard !chain.isEmpty, chain.count <= 16 else { throw MopError.invalidLocalIdentity }
        return chain
    }
}
extension LocalIdentity {
    public var certificateInfo: [LocalCertificateInfo] {
        get throws {
            guard case .certificate(let chain) = metadata else { throw MopError.localIdentityCapability }
            return try chain.map {
                let cert = try Certificate(derEncoded: Array($0))
                return LocalCertificateInfo(subject: String(describing: cert.subject), issuer: String(describing: cert.issuer), validFrom: cert.notValidBefore, validUntil: cert.notValidAfter, extensions: String(describing: cert.extensions), expired: cert.notValidAfter < Date())
            }
        }
    }
    public var certificatePEM: String {
        get throws {
            guard case .certificate(let chain) = metadata else { throw MopError.localIdentityCapability }
            return chain.map { PEMDocument(type: "CERTIFICATE", derBytes: Array($0)).pemString }.joined(separator: "\n")
        }
    }
}

private func derBytes<T: DERSerializable>(_ value: T) throws -> Data {
    var serializer = DER.Serializer(); try serializer.serialize(value); return Data(serializer.serializedBytes)
}

enum LocalCertificateValidation {
    static func validate(chain: [Data], publicKey: Data) throws {
        let certificates = try chain.map { try Certificate(derEncoded: Array($0)) }
        if let leaf = certificates.first {
            guard let key = P256.Signing.PublicKey(leaf.publicKey), key.x963Representation == publicKey else { throw MopError.invalidLocalIdentity }
        }
    }
}
