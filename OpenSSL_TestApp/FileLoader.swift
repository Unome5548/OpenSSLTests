//
//  FileLoader.swift
//  OpenSSL_TestApp
//
//  Created by Michael Patterson on 1/4/19.
//  Copyright © 2019 Microsoft. All rights reserved.
//

import Foundation

enum FileLoaderError: Error{
    case FileNotFound
    case Base64DecodeFailed
    case FailedToLoadURL
}

struct FileLoader{
    func getBase64DataFromFileWithExtension(fileName: String, extensionName: String) throws -> Data{
        
        guard let fileURL = Bundle.main.url(forResource: fileName, withExtension: extensionName)else{
            throw FileLoaderError.FileNotFound
        }
        
        let content = try String(contentsOf: fileURL, encoding: .utf8)
        
        guard let fileData = Data(base64Encoded: content, options: Data.Base64DecodingOptions.ignoreUnknownCharacters) else{
                throw FileLoaderError.Base64DecodeFailed
            }
        
        return fileData
    }
    
    func getDataFromFileWithExtension(fileName: String, extensionName: String) throws -> Data{
        guard let fileURL = Bundle.main.url(forResource: fileName, withExtension: extensionName)else{
            throw FileLoaderError.FileNotFound
        }
        
        let fileData = try Data(contentsOf: fileURL)
        
        return fileData
    }
}
