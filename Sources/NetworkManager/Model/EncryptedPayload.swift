//
//  File.swift
//  NetworkManager
//
//  Created by Batuhan Küçükyıldız on 1.04.2025.
//

import Foundation

public struct EncryptedPayload: Encodable {
    let encryptedAESKey: String
    let encryptedMessage: String
}
