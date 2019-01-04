//
//  ViewController.swift
//  C_Code_TestApp
//
//  Created by Michael Patterson on 1/2/19.
//  Copyright © 2019 Microsoft. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet weak var factorialTextField: UITextField!
    
    @IBOutlet weak var factorialGoButton: UIButton!
    
    @IBOutlet weak var factorialResultField: UITextView!
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        let fileLoader = FileLoader()
        let certTools = CertificateTools()
        
        do{

            let testCertData = try fileLoader.getBase64DataFromFileWithExtension(fileName: "TestCert", extensionName: "txt")
            
            let pkcs7Cert = try certTools.extractPKCS7Container(certData: testCertData)
            
            let rootCertData = try fileLoader.getDataFromFileWithExtension(fileName: "AppleIncRootCertificate", extensionName: "cer")
            
            let x509RootCert = try certTools.loadX509Certificate(certData: rootCertData)
            
            //Will always fail since we don't have the root certificate
//            try certTools.verifyAuthenticity(x509Certificate: x509RootCert, pkcs7Container: pkcs7Cert)
            
            try certTools.parse(pkcs7Container: pkcs7Cert)
            
            print("Complete")
        }catch{
            print("Error Caught \(error)")
        }
        
    }

    @IBAction func factorialGoButtonTapped(_ sender: Any) {
        
        guard let textInput = factorialTextField.text else {
            factorialResultField.text = "Input was empty"
            return
        }
        
        guard let input = Int32(textInput) else{
            factorialResultField.text = "Input was not a number"
            return
        }
        
        let result = factorial(input)
        factorialResultField.text = "\(result)"
    }
    
}

