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

    var hexString: String {
        return (self.data(using: String.Encoding.utf8)?.hexString)!
    }
    
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
        let keyData:Data = sha256(data: key.data(using: String.Encoding.utf8)!).subdata(in: 0..<MAXLENGTH/2)
        let keyStr = keyData.hexString;
        let newKey:Data = keyStr.data(using: .utf8)!;
        //let newKey:Data = keyData.subdata(in: 0..<MAXLENGTH)
        //let newKeyStr = newKey.hexString;
        
        //debugPrint(newKeyStr.substring(to: newKeyStr.index(newKeyStr.startIndex, offsetBy:MAXLENGTH)))
        //debugPrint(keyStr.substring(to: keyStr.index(keyStr.startIndex, offsetBy:MAXLENGTH)))
        debugPrint(newKey.hexString)
        debugPrint(newKey.base64EncodedString())
        
        //read the data from the source String using UTF Encoding
        let data:Data? = self.data(using: String.Encoding.utf8)
        
        //Check the length of the keyData
        let keyLength = newKey.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            throw AESError.KeyError(("Invalid key length", keyLength))
        }
        
        let ivSize = kCCBlockSizeAES128;
        var ivData = Data(count:ivSize);
        let cryptLength = size_t(ivSize + (data?.count)! + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)
        
        let status = ivData.withUnsafeMutableBytes {ivBytes in
            SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivBytes)
        }
        //debugPrint("Before Copy: destination variable has size of \(cryptData.count)")
        //debugPrint("Before Copy: destination value is \(cryptData.base64EncodedString())")
        debugPrint("IV variable has size of \(ivData.count)")
        debugPrint("IV value is \(ivData.base64EncodedString())")
        cryptData.withUnsafeMutableBytes{cryptBytes in
            ivData.copyBytes(to: cryptBytes, count: kCCBlockSizeAES128)
        }
        debugPrint("destination variable has size of \(cryptData.count)")
        debugPrint("destination value is \(cryptData.base64EncodedString())")
        if (status != 0) {
            throw AESError.IVError(("IV generation failed", Int(status)))
        }
        var numBytesEncrypted :Int = 0
        let dataCount = (data?.count ?? 0)
        debugPrint("Input data length : \(dataCount)")
        debugPrint("Input data : \(data?.base64EncodedString() ?? "No data")")
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            data?.withUnsafeBytes {dataBytes in
                newKey.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes, keyLength,
                            &ivData,
                            dataBytes, dataCount,
                            cryptBytes+kCCBlockSizeAES128, cryptLength,
                            &numBytesEncrypted)
                }
            }
        }
        debugPrint("Bytes Encrypted : \(numBytesEncrypted)")
        if UInt32(cryptStatus!) == UInt32(kCCSuccess) {
            debugPrint("Crypt Data has \(cryptData.count) bytes")
            debugPrint("Its encoded string is \(cryptData.base64EncodedString())")
            cryptData.count = numBytesEncrypted+kCCBlockSizeAES128
            debugPrint("Crypt Data has \(cryptData.count) bytes after adjustment")
            debugPrint("Its encoded string is \(cryptData.base64EncodedString()) after adjustment")

        } else {
            throw AESError.CryptorError(("Encryption failed", Int(cryptStatus!)))
        }
        
        return cryptData;
    }

    
    // The iv is prefixed to the encrypted data
    func aesCBCDecrypt(key:String) throws -> String? {
        let MAXLENGTH = 16
        
        //Generate a SHA256 Hash of the password
        let keyData:Data = sha256(data: key.data(using: String.Encoding.utf8)!).subdata(in: 0..<MAXLENGTH/2)
        let keyStr = keyData.hexString;
        let newKey:Data = keyStr.data(using: .utf8)!;
        debugPrint("keyData has size of : \(keyData.count) and newKey has a size of : \(newKey.count)")
        debugPrint(newKey.hexString)
        let data:Data? = Data(base64Encoded: self)

        let keyLength = newKey.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            throw AESError.KeyError(("Invalid key length", keyLength))
        }
        
        let ivSize = kCCBlockSizeAES128;
        var ivData = Data(count:ivSize);
        let clearLength = Int((data?.count)!)
        var clearData = Data(count:(clearLength+kCCBlockSizeAES128))

        debugPrint("Blank IV variable has size of \(ivData.count)")
        debugPrint("Blank IV value is \(ivData.base64EncodedString())")
        ivData.withUnsafeMutableBytes{ivBytes in
            data?.copyBytes(to: ivBytes, count: kCCBlockSizeAES128)
        }
        debugPrint("Copied IV variable has size of \(ivData.count)")
        debugPrint("Copied IV value is \(ivData.base64EncodedString())")
        debugPrint("Size of clear data is \(clearLength)")
        debugPrint("Contents of clear data are \(clearData.base64EncodedString())")
        var numBytesDecrypted :Int = 0
        //let options   = CCOptions(kCCOptionPKCS7Padding)
        debugPrint("Bytes decrypted before are \(numBytesDecrypted)")
        let cryptStatus = clearData.withUnsafeMutableBytes {clearBytes in
            data?.withUnsafeBytes {dataBytes in
                ivData.withUnsafeBytes {ivBytes in
                    newKey.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES128),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes+kCCBlockSizeAES128, clearLength,
                                clearBytes, clearLength,
                                &numBytesDecrypted)
                    }
                }
            }
        }
        
        if UInt32(cryptStatus!) == UInt32(kCCSuccess) {
            debugPrint("Bytes decrypted after are \(numBytesDecrypted)")
            debugPrint("Size of clear data is \(clearData.count)")
            debugPrint("Contents of clear data are \(clearData.base64EncodedString())")
            clearData.count = numBytesDecrypted
            debugPrint(numBytesDecrypted)
            debugPrint("Size of clear data is \(clearData.count)")
            debugPrint("Contents of clear data are \(clearData.base64EncodedString())")
            debugPrint(String(data:clearData, encoding: .utf8) ?? "No conversion")
        }
        else {
            throw AESError.CryptorError(("Decryption failed", Int(cryptStatus!)))
        }
        return String(data:clearData, encoding: .utf8);
    }
}
