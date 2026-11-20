import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum CompatibilityError: Int32, Error {
    case invalidData = -26275
    case unavailable = -25291
}

struct BiometricEnvelope: Codable {
    let enclaveKey: Data
    let ephemeralPublicKey: Data
    let sealedKey: Data

    static let vaultKeyLength = 32
    static let maximumEncodedLength = 4096

    static func make(vaultKey: Data, account: Data) throws -> BiometricEnvelope {
        guard SecureEnclave.isAvailable else { throw CompatibilityError.unavailable }
        guard vaultKey.count == vaultKeyLength, (1...128).contains(account.count),
              let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet], nil
              ) else { throw CompatibilityError.invalidData }

        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeralKey = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeralKey.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let binding = Self.binding(account)
        let encrypted = try AES.GCM.seal(vaultKey, using: Self.aesKey(secret, binding),
                                        authenticating: binding)
        guard let combined = encrypted.combined else { throw CompatibilityError.invalidData }
        return BiometricEnvelope(enclaveKey: enclaveKey.dataRepresentation,
                                 ephemeralPublicKey: ephemeralKey.publicKey.x963Representation,
                                 sealedKey: combined)
    }

    func open(account: Data, context: LAContext) throws -> Data {
        guard SecureEnclave.isAvailable else { throw CompatibilityError.unavailable }
        guard (1...128).contains(account.count), (1...2048).contains(enclaveKey.count),
              ephemeralPublicKey.count == 65, sealedKey.count == 60 else {
            throw CompatibilityError.invalidData
        }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        let box = try AES.GCM.SealedBox(combined: sealedKey)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: enclaveKey, authenticationContext: context)
        // The Enclave enforces the biometric policy at the private-key operation.
        let secret = try key.sharedSecretFromKeyAgreement(with: peer)
        let binding = Self.binding(account)
        return try AES.GCM.open(box, using: Self.aesKey(secret, binding), authenticating: binding)
    }

    private static func binding(_ account: Data) -> Data {
        Data("com.fluxlock.touchid-compatibility.v1\0".utf8) + account
    }

    private static func aesKey(_ secret: SharedSecret, _ binding: Data) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(),
                                       sharedInfo: binding, outputByteCount: 32)
    }
}

private func contextForTouchID(_ reason: String) -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.localizedFallbackTitle = ""
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
}

private func compatibilityStatus(_ error: Error) -> Int32 {
    if let error = error as? CompatibilityError { return error.rawValue }
    let nsError = error as NSError
    if (nsError.domain == LAError.errorDomain &&
        [LAError.userCancel.rawValue, LAError.systemCancel.rawValue, LAError.appCancel.rawValue]
            .contains(nsError.code)) ||
        (nsError.domain == NSOSStatusErrorDomain && nsError.code == Int(errSecUserCanceled)) {
        return errSecUserCanceled
    }
    return errSecAuthFailed
}

@_cdecl("fluxlock_compatibility_is_available")
func fluxlockCompatibilityIsAvailable() -> Bool {
    SecureEnclave.isAvailable
}

@_cdecl("fluxlock_compatibility_seal")
func fluxlockCompatibilitySeal(
    _ key: UnsafePointer<UInt8>, _ keyLength: Int32,
    _ account: UnsafePointer<UInt8>, _ accountLength: Int32,
    _ output: UnsafeMutablePointer<UInt8>, _ capacity: Int32
) -> Int32 {
    guard keyLength == BiometricEnvelope.vaultKeyLength, (1...128).contains(accountLength),
          capacity >= BiometricEnvelope.maximumEncodedLength else {
        return CompatibilityError.invalidData.rawValue
    }
    let binding = Data(bytes: account, count: Int(accountLength))
    let keyBytes = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: key),
                        count: Int(keyLength), deallocator: .none)
    do {
        let envelope = try BiometricEnvelope.make(vaultKey: keyBytes, account: binding)
        let context = contextForTouchID("Activez Touch ID pour le coffre FluXlock")
        defer { context.invalidate() }
        var verification = try envelope.open(account: binding, context: context)
        defer { verification.resetBytes(in: 0..<verification.count) }
        guard verification == keyBytes else { throw CompatibilityError.invalidData }
        let encoded = try JSONEncoder().encode(envelope)
        guard encoded.count <= BiometricEnvelope.maximumEncodedLength else {
            throw CompatibilityError.invalidData
        }
        encoded.copyBytes(to: output, count: encoded.count)
        return Int32(encoded.count)
    } catch {
        return compatibilityStatus(error)
    }
}

@_cdecl("fluxlock_compatibility_open")
func fluxlockCompatibilityOpen(
    _ input: UnsafePointer<UInt8>, _ inputLength: Int32,
    _ account: UnsafePointer<UInt8>, _ accountLength: Int32,
    _ output: UnsafeMutablePointer<UInt8>, _ capacity: Int32
) -> Int32 {
    guard (1...Int32(BiometricEnvelope.maximumEncodedLength)).contains(inputLength),
          (1...128).contains(accountLength), capacity == BiometricEnvelope.vaultKeyLength else {
        return CompatibilityError.invalidData.rawValue
    }
    let context = contextForTouchID("Déverrouillez le coffre FluXlock avec Touch ID")
    defer { context.invalidate() }
    do {
        let encoded = Data(bytes: input, count: Int(inputLength))
        let envelope = try JSONDecoder().decode(BiometricEnvelope.self, from: encoded)
        var clearKey = try envelope.open(account: Data(bytes: account, count: Int(accountLength)),
                                         context: context)
        defer { clearKey.resetBytes(in: 0..<clearKey.count) }
        guard clearKey.count == BiometricEnvelope.vaultKeyLength else {
            throw CompatibilityError.invalidData
        }
        clearKey.copyBytes(to: output, count: clearKey.count)
        return Int32(clearKey.count)
    } catch {
        return compatibilityStatus(error)
    }
}
