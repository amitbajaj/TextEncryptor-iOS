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

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        let tap: UITapGestureRecognizer = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
        
        //Uncomment the line below if you want the tap not not interfere and cancel other interactions.
        tap.cancelsTouchesInView = false
        
        view.addGestureRecognizer(tap)
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    func dismissKeyboard(){
        view.endEditing(true)
    }

    
    
    @IBOutlet weak var txtSource: UITextView!
    @IBOutlet weak var tblCellCopyPasteArea: UITableViewCell!
    
    @IBOutlet weak var txtPassField: UITextField!
    
    @IBAction func doCopy(_ sender: UIButton){
        let clipBoard = UIPasteboard.general
        clipBoard.string = txtSource.text
    }
    
    @IBAction func doPaste(_ sender: UIButton){
        let clipBoard = UIPasteboard.general
        txtSource.text = clipBoard.string
    }
    
    @IBAction func doEncrypt(_ sender: UIButton) {
        let ae = AESEncryption();
        let encData:Data;

        do{
            encData = try ae.aesCBCEncrypt(data: (txtSource.text?.data(using: String.Encoding.utf8))!, keyDataP: (txtPassField.text?.data(using: String.Encoding.utf8))!);

            txtSource.text = encData.base64EncodedString()
            //txtSource.text = try txtSource.text.aesCBCEncrypt(key: txtPassField.text!).base64EncodedString();
            /*
            let alertController = UIAlertController(title: "Destructive", message: "Simple alertView demo with Destructive and Ok.", preferredStyle: UIAlertControllerStyle.alert)
            
            let okAction = UIAlertAction(title: "OK", style: UIAlertActionStyle.default) {
                (result : UIAlertAction) -> Void in
                print("OK")
            }
            
            alertController.addAction(okAction)
            self.present(alertController, animated: true, completion: nil)
            */
            
        }catch let error{
            debugPrint(error.localizedDescription)
        }
    }

    @IBAction func doDecrypt(_ sender: UIButton) {
        let ae = AESEncryption();
        let decData:Data;
        do{
            decData = try ae.aesCBCDecrypt(data: Data(base64Encoded: txtSource.text)!, keyDataP: (txtPassField.text?.data(using: String.Encoding.utf8))!)!
            txtSource.text = String(data: decData, encoding: .utf8);
            //txtSource.text = try txtSource.text.aesCBCDecrypt(key: txtPassField.text!)
        }catch let error{
            debugPrint(error.localizedDescription)
        }
    }

}
