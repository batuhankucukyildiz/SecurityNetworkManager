//
//  EndpointProtocol.swift
//
//
//  Created by Batuhan Küçükyıldız on 24.04.2024.
//

import Foundation

public protocol EndpointProtocol {
    var baseURL: String { get }
    var path: String { get }
    var httpMethod: HttpMethods { get }
    var headers: [String: String]? { get }
    var body: Encodable? { get }

    func url() throws -> URL
}
