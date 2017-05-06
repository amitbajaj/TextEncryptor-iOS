//
//  Encryptor.swift
//  TextEncryptor
//
//  Created by Amit Bajaj on 5/4/17.
//  Copyright © 2017 online.buzzzz.security. All rights reserved.
//

import Foundation

extension Data {
    var hexString: String {
        return self.reduce("") { $0 + String(format: "%02x", $1) }
    }
}

extension String {

    
    func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash)
    }
    
    enum AESError: Error {
        case KeyError((String, Int))
        case IVError((String, Int))
        case CryptorError((String, Int))
    }

    // The iv is prefixed to the encrypted data
    func aesCBCEncrypt(key:String) throws -> Data {
        let MAXLENGTH = 16

        //Generate a SHA256 Hash of the password
        let keyData:Data = sha256(data: key.data(using: String.Encoding.utf8)!)
        let newKey:Data = keyData.subdata(in: 0..<MAXLENGTH)
        debugPrint("keyData has size of : \(keyData.count) and newKey has a size of : \(newKey.count)")
        debugPrint(keyData.hexString)
        debugPrint(newKey.hexString)
        
        //read the data from the source String using UTF Encoding
        let data:Data? = self.data(using: String.Encoding.utf8)
        
        //Check the length of the keyData
        let keyLength = newKey.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            throw AESError.KeyError(("Invalid key length", keyLength))
        }
        
        let ivSize = kCCBlockSizeAES128;
        let cryptLength = size_t(ivSize + (data?.count)! + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)
        
        let status = cryptData.withUnsafeMutableBytes {ivBytes in
            SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivBytes)
        }
        debugPrint(cryptData.count)
        debugPrint(cryptData.base64EncodedString())
        if (status != 0) {
            throw AESError.IVError(("IV generation failed", Int(status)))
        }
        
        var numBytesEncrypted :size_t = 0
        //let options   = CCOptions(kCCOptionPKCS7Padding)
        debugPrint((data?.count)!)
        debugPrint(data?.base64EncodedString() ?? "No data")
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            data?.withUnsafeBytes {dataBytes in
                newKey.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes, keyLength,
                            cryptBytes,
                            dataBytes, (data?.count)!,
                            cryptBytes+kCCBlockSizeAES128, cryptLength,
                            &numBytesEncrypted)
                }
            }
        }
        
        if UInt32(cryptStatus!) == UInt32(kCCSuccess) {
            debugPrint(cryptData.count)
            debugPrint(cryptData.base64EncodedString())
            cryptData.count = numBytesEncrypted + ivSize
            debugPrint(cryptData.count)
            debugPrint(cryptData.base64EncodedString())        }
        else {
            throw AESError.CryptorError(("Encryption failed", Int(cryptStatus!)))
        }
        
        return cryptData;
    }

    
    // The iv is prefixed to the encrypted data
    func aesCBCDecrypt(key:String) throws -> String? {
        let MAXLENGTH = 16
        
        //Generate a SHA256 Hash of the password
        let keyData:Data = sha256(data: key.data(using: String.Encoding.utf8)!)
        let newKey:Data = keyData.subdata(in: 0..<MAXLENGTH)
        debugPrint("keyData has size of : \(keyData.count) and newKey has a size of : \(newKey.count)")
        debugPrint(newKey.hexString)
        let data:Data? = self.data(using: String.Encoding.utf8)

        let keyLength = newKey.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            throw AESError.KeyError(("Invalid key length", keyLength))
        }
        
        let ivSize = kCCBlockSizeAES128;
        let clearLength = size_t((data?.count)! - ivSize)
        var clearData = Data(count:clearLength)
        
        var numBytesDecrypted :size_t = 0
        //let options   = CCOptions(kCCOptionPKCS7Padding)
        
        let cryptStatus = clearData.withUnsafeMutableBytes {cryptBytes in
            data?.withUnsafeBytes {dataBytes in
                newKey.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
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
            debugPrint(numBytesDecrypted)
            debugPrint(clearData.count)
            debugPrint(clearData.base64EncodedString())
        }
        else {
            throw AESError.CryptorError(("Decryption failed", Int(cryptStatus!)))
        }
        
        return String(data:clearData, encoding: .utf8);
    }
    
}
