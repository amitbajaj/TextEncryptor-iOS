//
//  Encryptor-v1.swift
//  TextEncryptor
//
//  Created by Amit Bajaj on 5/12/17.
//  Copyright © 2017 online.buzzzz.security. All rights reserved.
//

import Foundation
class AESEncryption{
    let MAXLENGTH = 16;
    
    enum AESError: Error {
        case KeyError((String, Int))
        case IVError((String, Int))
        case CryptorError((String, Int))
    }
    //calculate the sha256 hash for the given data and return the Hex ecoded string
    func sha256inHex(data : Data) -> String {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash).reduce("", { $0 + String(format: "%02x", $1) })
    }
    
    // The iv is prefixed to the encrypted data
    func aesCBCEncrypt(data:Data, keyDataP:Data) throws -> Data {
        let keyHash = sha256inHex(data: keyDataP)
        let keyData = keyHash.substring(to: keyHash.index(keyHash.startIndex, offsetBy:MAXLENGTH)).data(using: .utf8)
        let keyLength = keyData!.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            throw AESError.KeyError(("Invalid key length", keyLength))
        }
        
        let ivSize = kCCBlockSizeAES128;
        let cryptLength = size_t(ivSize + data.count + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)
        
        let status = cryptData.withUnsafeMutableBytes {ivBytes in
            SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivBytes)
        }
        if (status != 0) {
            throw AESError.IVError(("IV generation failed", Int(status)))
        }
        
        var numBytesEncrypted :size_t = 0
        let options   = CCOptions(kCCOptionPKCS7Padding)
        
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                keyData?.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            options,
                            keyBytes, keyLength,
                            cryptBytes,
                            dataBytes, data.count,
                            cryptBytes+kCCBlockSizeAES128, cryptLength,
                            &numBytesEncrypted)
                }
            }
        }
        if UInt32(cryptStatus!) == UInt32(kCCSuccess) {
            cryptData.count = numBytesEncrypted + ivSize
        }
        else {
            throw AESError.CryptorError(("Encryption failed", Int(cryptStatus!)))
        }
        return cryptData;
    }
    // The iv is prefixed to the encrypted data
    func aesCBCDecrypt(data:Data, keyDataP:Data) throws -> Data? {
        let keyHash = sha256inHex(data: keyDataP)
        let keyData = keyHash.substring(to: keyHash.index(keyHash.startIndex, offsetBy:MAXLENGTH)).data(using: .utf8)
        let keyLength = keyData!.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            throw AESError.KeyError(("Invalid key length", keyLength))
        }
        let ivSize = kCCBlockSizeAES128;
        let clearLength = size_t(data.count - ivSize)
        if clearLength <= 0 {
            throw AESError.CryptorError(("No data",100))
        }
        var clearData = Data(count:clearLength)
        
        var numBytesDecrypted :size_t = 0
        let options   = CCOptions(kCCOptionPKCS7Padding)
        
        let cryptStatus = clearData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                keyData?.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            options,
                            keyBytes, keyLength,
                            dataBytes,
                            dataBytes+kCCBlockSizeAES128, clearLength,
                            cryptBytes, clearLength,
                            &numBytesDecrypted)
                }
            }
        }
        if UInt32(cryptStatus!) == UInt32(kCCSuccess) {
            clearData.count = numBytesDecrypted
        }
        else {
            throw AESError.CryptorError(("Decryption failed", Int(cryptStatus!)))
        }
        
        return clearData;
    }
}
