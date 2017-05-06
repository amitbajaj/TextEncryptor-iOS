//
//  TextEncryptor.swift
//  TextEncryptor
//
//  Created by Amit Bajaj on 5/1/17.
//  Copyright © 2017 online.buzzzz.security. All rights reserved.
//

import Foundation
import UIKit


class TextEncryptor: UITableViewController{

    @IBOutlet weak var txtSource: UITextView!
    
    @IBOutlet weak var txtPassField: UITextField!
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }
    
    @IBAction func doEncrypt(_ sender: UIButton) {
        do{
            txtSource.text = try txtSource.text.aesCBCEncrypt(key: txtPassField.text!).base64EncodedString()
        }catch let error{
            debugPrint(error.localizedDescription)
        }
    }

    @IBAction func doDecrypt(_ sender: UIButton) {
        do{
            txtSource.text = try txtSource.text.aesCBCDecrypt(key: txtPassField.text!)
        }catch let error{
            debugPrint(error.localizedDescription)
        }
    }

}
