//
//  Crypto.swift
//  OneTimePassword
//
//  Copyright (c) 2016-2018 Matt Rubin and the OneTimePassword authors
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

import Foundation
import Cryptor
typealias _HMAC = HMAC

func HMAC(algorithm: Generator.Algorithm, key: Data, data: Data) -> Data {
    
    let algo = algorithm.hashInfo
    
    guard let macOut = _HMAC(using: algo, key: key).update(data: data)?.final() else {
        fatalError("Failed to calculate HMAC")
    }

    return Data(bytes: macOut, count: algo.digestLength())
}

private extension Generator.Algorithm {
    /// The corresponding CommonCrypto hash function and hash length.
    var hashInfo: HMAC.Algorithm {
        switch self {
        case .sha1:
            return .sha1
        case .sha256:
            return .sha256
        case .sha512:
            return .sha512
        }
    }
}
