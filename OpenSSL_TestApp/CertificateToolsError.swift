//
//  CertificateLoaderError.swift
//  OpenSSL_TestApp
//
//  Created by Michael Patterson on 1/4/19.
//  Copyright © 2019 Microsoft. All rights reserved.
//

import Foundation

enum CertificateToolsError: Error{
    case emptyCertificate
    case certNotSigned
    case signatureInvalid
    case malformedStructureWhenParsing
}
