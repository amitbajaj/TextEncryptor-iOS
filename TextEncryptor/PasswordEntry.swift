//
//  PasswordEntry.swift
//  TextEncryptor
//
//  Created by Amit Bajaj on 5/30/17.
//  Copyright © 2017 online.buzzzz.security. All rights reserved.
//

import Foundation
import UIKit

class PasswordEntry: UIViewController{
    @IBOutlet weak var btnValidate: UIButton!
    @IBOutlet weak var txtPIN: UITextField!
    var userPIN = ""
    var newPIN = ""
    var isPINset = false
    var newPinStage = 0
    var numberOfPinTries = 0
    var pinValidated = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        txtPIN.becomeFirstResponder()
        let defaults = UserDefaults.standard
        isPINset = defaults.bool(forKey: "isPINset")
        debugPrint(isPINset)
        //isPINset = false
        if(isPINset){
            userPIN = defaults.string(forKey: "userPIN") ?? ""
            debugPrint(userPIN)
            if(userPIN.characters.count == 0){
                txtPIN.placeholder = "Set a new PIN"
                isPINset=false
            }
        }else{
            txtPIN.placeholder = "Set a new PIN"
        }
        if(!(isPINset)){
            btnValidate.setTitle("Set New PIN", for: UIControlState.normal)
        }
        //self.view.setNeedsDisplay()
    }
    
    func closeMe(){
        let defaults = UserDefaults.standard
        if(pinValidated && newPinStage == 1){
            defaults.set(true, forKey: "isPINset")
            defaults.set(newPIN, forKey: "userPIN")
        }
        self.performSegue(withIdentifier: "restoreBackTheMainScreen", sender: self)
    }
    
    @IBAction func cancelPinValidation(){
        closeMe()
    }
    
    @IBAction func checkPin(){
        if(isPINset){
            //debugPrint("User PIN in settings is \(userPIN) and that entered by user is \(txtPIN.text!)")
            if(txtPIN.text == userPIN){
                newPIN = userPIN
                pinValidated=true
                closeMe()
            }else{
                numberOfPinTries = numberOfPinTries+1
                if(numberOfPinTries>=3){
                    pinValidated = false
                    closeMe()
                }else{
                    txtPIN.placeholder = "Retry...."
                    txtPIN.text = ""
                }
            }
        }else{
            if(newPinStage == 0){
                newPinStage = 1
                newPIN = txtPIN.text!
                txtPIN.text = ""
                btnValidate.setTitle("Re-enter PIN", for: UIControlState.normal)
            }else{
                if(newPIN == txtPIN.text!){
                    pinValidated = true
                    closeMe()
                }else{
                    txtPIN.text = ""
                    newPIN = ""
                    txtPIN.placeholder = "PIN Mismatch - try again"
                    newPinStage = 0
                    btnValidate.setTitle("Set New PIN", for: UIControlState.normal)
                }
            }
        }
        self.view.setNeedsDisplay()
    }
}
