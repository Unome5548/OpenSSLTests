//
//  CertificateLoader.swift
//  OpenSSL_TestApp
//
//  Created by Michael Patterson on 1/4/19.
//  Copyright © 2019 Microsoft. All rights reserved.
//

import Foundation

struct CertificateTools{
    //TODO: Do we want to keep the name Extract or Load?
    func extractPKCS7Container( certData: Data) throws -> UnsafeMutablePointer<PKCS7>{
        
        //BIO stands for basic I/O. This line creates a new object that uses memory for its I/O operations
        let certBIO = BIO_new(BIO_s_mem())
        //Writes the data into the Basic IO object
        BIO_write(certBIO, (certData as NSData).bytes, Int32(certData.count))
        //Creates a PKCS7 container from a Basic IO object
        let certPKCS7Container: UnsafeMutablePointer<PKCS7> = d2i_PKCS7_bio(certBIO, nil)
        
        guard certPKCS7Container != nil else {
            print("Empty Receipt Contents")
            throw CertificateToolsError.emptyCertificate
        }
        
        let pkcs7DataTypeCode = OBJ_obj2nid(pkcs7_d_sign(certPKCS7Container).pointee.contents.pointee.type)
        
        guard pkcs7DataTypeCode == NID_pkcs7_data else {
            print("Error")
            throw CertificateToolsError.emptyCertificate
        }
        
        //Validate the Certificate is Signed
        try checkSignaturePresence(pkcs7Cert: certPKCS7Container)
        
        return certPKCS7Container
    }
    
    func loadX509Certificate( certData: Data) throws -> UnsafeMutablePointer<X509>{
        
        let certBIO = BIO_new(BIO_s_mem())
        
        BIO_write(certBIO, (certData as NSData).bytes, Int32(certData.count))
        
        let certX509Container: UnsafeMutablePointer<X509> = d2i_X509_bio(certBIO, nil)
        
        return certX509Container
    }
    
    func checkSignaturePresence( pkcs7Cert: UnsafeMutablePointer<PKCS7>) throws{
        let pkcs7SignedTypeCode = OBJ_obj2nid(pkcs7Cert.pointee.type)
        
        guard pkcs7SignedTypeCode == NID_pkcs7_signed else{
            throw CertificateToolsError.certNotSigned
        }
    }
    
    //Compare a PKCS7 Certificate against a x509 Root Certificate
    func verifyAuthenticity(x509Certificate: UnsafeMutablePointer<X509>, pkcs7Container: UnsafeMutablePointer<PKCS7>) throws{
        
        let x509CertificateStore = X509_STORE_new()
        
        X509_STORE_add_cert(x509CertificateStore, x509Certificate)
        
        OpenSSL_add_all_digests()
        
        //PKCS7_verify returns 0 for successful, and one for an error
        let result = PKCS7_verify(pkcs7Container, nil, x509CertificateStore, nil, nil, 0)
        
        if result != 1 {
            let buffer:UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.allocate(capacity: 100)
            ERR_error_string(ERR_get_error(), buffer)
            let errorString = String(cString: buffer)
            
            throw CertificateToolsError.signatureInvalid
        }
    }
    
    func parse(pkcs7Container: UnsafeMutablePointer<PKCS7>) throws{
        guard let contents = pkcs7Container.pointee.d.sign.pointee.contents else{
            throw CertificateToolsError.malformedStructureWhenParsing
        }
        
        guard let octets = contents.pointee.d.data else{
            throw CertificateToolsError.malformedStructureWhenParsing
        }
        
        var currentASN1PayloadLocation = UnsafePointer(octets.pointee.data)
        let endOfPayload = currentASN1PayloadLocation!.advanced(by: Int(octets.pointee.length))
        
        var type = Int32(0)
        var xclass = Int32(0)
        var length = 0
        
        ASN1_get_object(&currentASN1PayloadLocation, &length, &type, &xclass, Int(octets.pointee.length))
        
        guard type == V_ASN1_SET else{
            throw CertificateToolsError.malformedStructureWhenParsing
        }
        
        while currentASN1PayloadLocation! < endOfPayload{
            // Get next ASN1 Sequence
            ASN1_get_object(&currentASN1PayloadLocation, &length, &type, &xclass, currentASN1PayloadLocation!.distance(to: endOfPayload))
            
            // ASN1 Object type must be an ASN1 Sequence
            guard type == V_ASN1_SEQUENCE else {
                throw CertificateToolsError.malformedStructureWhenParsing
            }
            
            // Attribute type of ASN1 Sequence must be an Integer
            guard let attributeType = DecodeASN1Integer(startOfInt: &currentASN1PayloadLocation, length: currentASN1PayloadLocation!.distance(to: endOfPayload)) else {
                throw CertificateToolsError.malformedStructureWhenParsing
            }
            
            // Attribute version of ASN1 Sequence must be an Integer
            guard DecodeASN1Integer(startOfInt: &currentASN1PayloadLocation, length: currentASN1PayloadLocation!.distance(to: endOfPayload)) != nil else {
                throw CertificateToolsError.malformedStructureWhenParsing
            }
            
            // Get ASN1 Sequence value
            ASN1_get_object(&currentASN1PayloadLocation, &length, &type, &xclass, currentASN1PayloadLocation!.distance(to: endOfPayload))
            
            // ASN1 Sequence value must be an ASN1 Octet String
            guard type == V_ASN1_OCTET_STRING else {
                throw CertificateToolsError.malformedStructureWhenParsing
            }
            
            switch attributeType {
            default:
                break
            }
        }
    }
    
    func DecodeASN1Integer(startOfInt intPointer: inout UnsafePointer<UInt8>?, length: Int) -> Int? {
        // These will be set by ASN1_get_object
        var type = Int32(0)
        var xclass = Int32(0)
        var intLength = 0
        
        ASN1_get_object(&intPointer, &intLength, &type, &xclass, length)
        
        guard type == V_ASN1_INTEGER else {
            return nil
        }
        
        let integer = c2i_ASN1_INTEGER(nil, &intPointer, intLength)
        let result = ASN1_INTEGER_get(integer)
        ASN1_INTEGER_free(integer)
        
        return result
    }
    
    func DecodeASN1String(startOfString stringPointer: inout UnsafePointer<UInt8>?, length: Int) -> String? {
        // These will be set by ASN1_get_object
        var type = Int32(0)
        var xclass = Int32(0)
        var stringLength = 0
        
        ASN1_get_object(&stringPointer, &stringLength, &type, &xclass, length)
        
        if type == V_ASN1_UTF8STRING {
            let mutableStringPointer = UnsafeMutableRawPointer(mutating: stringPointer!)
            return String(bytesNoCopy: mutableStringPointer, length: stringLength, encoding: String.Encoding.utf8, freeWhenDone: false)
        }
        
        if type == V_ASN1_IA5STRING {
            let mutableStringPointer = UnsafeMutableRawPointer(mutating: stringPointer!)
            return String(bytesNoCopy: mutableStringPointer, length: stringLength, encoding: String.Encoding.ascii, freeWhenDone: false)
        }
        
        return nil
    }
    
    func DecodeASN1Date(startOfDate datePointer: inout UnsafePointer<UInt8>?, length: Int) -> Date? {
        // Date formatter code from https://www.objc.io/issues/17-security/receipt-validation/#parsing-the-receipt
        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
        
        if let dateString = DecodeASN1String(startOfString: &datePointer, length:length) {
            return dateFormatter.date(from: dateString)
        }
        
        return nil
    }
}
