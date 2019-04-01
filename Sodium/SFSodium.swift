//
//  SFSodium.swift
//  Sodium
//
//  Created by Konstantin Victorovich Erokhin on 3/25/2019.
//  Copyright © 2019 Frank Denis. All rights reserved.
//

import Foundation

@objc
public class SFSodium : NSObject {
    
    @objc
    public func encrypt(message: String, secretKey: Bytes) -> (NSData)? {
        
        let sodium = Sodium()
        
        if (secretKey.count != sodium.secretBox.KeyBytes)
        {
            // making sure that the secretKey is of the right length; it should be
            // generated using secretKey(password:salt:)
            return nil
        }
        
        let messageBytes = message.bytes
        let encrypted: Bytes = sodium.secretBox.seal(message: messageBytes, secretKey: secretKey)!
        
        // we will return the encrypted NSData object
        let data = Data(encrypted)
        return NSData(data: data)
    }
    
    @objc
    public func decrypt(messageData: NSData, secretKey: Bytes) -> (String)? {
        
        let sodium = Sodium()
        
        if (secretKey.count != sodium.secretBox.KeyBytes)
        {
            // making sure that the secretKey is of the right length; it should be
            // generated using secretKey(password:salt:)
            return nil
        }
        
        // we have to get the Bytes from the Data object
        let messageIntermediateData = Data(referencing: messageData)
        var message = [UInt8]()
        message.append(contentsOf: messageIntermediateData)
        
        if let decrypted = sodium.secretBox.open(nonceAndAuthenticatedCipherText: message, secretKey: secretKey) {
            // authenticator is valid, decrypted contains the original message
            return decrypted.utf8String;
        }
        return nil
    }
    
    @objc
    public func secretKey(password: String, salt: String) -> (Bytes)? {
        let sodium = Sodium()
        let passwordBytes = password.bytes
        var saltBytes = salt.bytes
        
        // we will make sure that the salt is of the appropriate size, duplicating it...
        while (saltBytes.count > 0
            && saltBytes.count < sodium.pwHash.SaltBytes)
        {
            saltBytes.append(contentsOf: saltBytes)
        }
        // ... and truncating it at the end
        if (saltBytes.count > sodium.pwHash.SaltBytes)
        {
            saltBytes = Bytes(saltBytes.prefix(sodium.pwHash.SaltBytes))
        }
        
        // the real hash generation
        let hash = sodium.pwHash.hash(outputLength: sodium.secretBox.KeyBytes,
                                      passwd: passwordBytes,
                                      salt: saltBytes,
                                      opsLimit: sodium.pwHash.OpsLimitInteractive,
                                      memLimit: sodium.pwHash.MemLimitInteractive,
                                      alg: PWHash.Alg.Argon2ID13)
        
        return hash
    }
}
