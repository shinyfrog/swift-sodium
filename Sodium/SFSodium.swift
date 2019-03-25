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
    public func hash(password: String, salt: String) -> (String)? {
        let sodium = Sodium()
        let passwordBytes = password.bytes
        var saltBytes = salt.bytes
        
        // we will make sure that the salt is of the appropriate size, duplicating it...
        while (saltBytes.count > 0
            && saltBytes.count < sodium.pwHash.SaltBytes)
        {
            saltBytes.append(contentsOf: saltBytes);
        }
        // ... and truncating it at the end
        if (saltBytes.count > sodium.pwHash.SaltBytes)
        {
            saltBytes = Bytes(saltBytes.prefix(sodium.pwHash.SaltBytes))
        }
        
        // the real hash generation
        let hash = sodium.pwHash.hash(outputLength: 32,
                                      passwd: passwordBytes,
                                      salt: saltBytes,
                                      opsLimit: sodium.pwHash.OpsLimitInteractive,
                                      memLimit: sodium.pwHash.MemLimitInteractive)
        
        if (hash != nil)
        {
            // we will return the ASCII encoded string for the hash bytes
            return String(bytes: hash!, encoding: String.Encoding.ascii)
        }
        return nil
    }
}
