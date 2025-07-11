import UIKit
import CryptoKit
import Security

final public class SecurityNetworkManager {
    private init() {}

    public static let shared: SecurityNetworkManager = SecurityNetworkManager()

    private let jsonDecoder = JSONDecoder()

    private let session: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 15
        return URLSession(configuration: configuration)
    }()

    public func request<T: Decodable>(
        _ endpoint: EndpointProtocol,
        rsaPublicKey: SecKey? = nil
    ) async throws -> T {

        var requestBodyData: Data?

        if let body = endpoint.body {
            if let rsaKey = rsaPublicKey {
                let encryptedPayload = try encryptPayload(body, rsaPublicKey: rsaKey)
                requestBodyData = try JSONEncoder().encode(encryptedPayload)
            } else {
                requestBodyData = try JSONEncoder().encode(body)
            }
        }

        var request = try URLRequest(url: endpoint.url())
        request.httpMethod = endpoint.httpMethod.rawValue
        request.httpBody = requestBodyData

        var headers: [String: String] = ["Content-Type": "application/json"]
        if let customHeaders = endpoint.headers {
            customHeaders.forEach { key, value in
                headers[key] = value
            }
        }
        request.allHTTPHeaderFields = headers

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponse(description: "Invalid Response")
        }

        _ = try await handleNetworkRequest(response: httpResponse, data: data)

        return try jsonDecoder.decode(T.self, from: data)
    }

    private func handleNetworkRequest(response: HTTPURLResponse, data: Data) async throws -> String {
        switch response.statusCode {
        case 200...299:
            return "Request Success"
        case 400...599:
            if let errorResponse = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                throw errorResponse
            } else {
                throw NetworkError.invalidResponse(description: "Unable to decode error response")
            }
        default:
            throw NetworkError.networkError(code: 500)
        }
    }
}


extension SecurityNetworkManager {
    public func encryptPayload<T: Encodable>(_ body: T, rsaPublicKey: SecKey) throws -> EncryptedPayload {
        let symmetricKey = SymmetricKey(size: .bits256)
        let aesKeyData = symmetricKey.withUnsafeBytes { Data($0) }

        let jsonData = try JSONEncoder().encode(body)

        let sealedBox = try AES.GCM.seal(jsonData, using: symmetricKey)

        guard let combined = sealedBox.combined else {
            throw NSError(domain: "EncryptionError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to get combined encrypted data"])
        }

        var error: Unmanaged<CFError>?
        guard let encryptedAESKey = SecKeyCreateEncryptedData(
            rsaPublicKey,
            .rsaEncryptionPKCS1,
            aesKeyData as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue()
        }

        return EncryptedPayload(
            encryptedAESKey: encryptedAESKey.base64EncodedString(),
            encryptedMessage: combined.base64EncodedString()
        )
    }
}
