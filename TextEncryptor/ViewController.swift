//
//  ViewController.swift
//  TextEncryptor
//
//  Created by Amit Bajaj on 5/24/17.
//  Copyright © 2017 online.buzzzz.security. All rights reserved.
//

import GoogleAPIClientForREST
import GoogleSignIn
import Foundation
import UIKit

class ViewController: UIViewController, GIDSignInDelegate, GIDSignInUIDelegate{
    private let scopes = [kGTLRAuthScopeDrive,kGTLRAuthScopeDriveMetadata]
    private let service = GTLRDriveService()
    private let FILENAME = "TextEncryptor"
    private let MIMETYPE = "text/plain"
    private var wait: UIAlertController? = nil
    //let signInButton = GIDSignInButton()
    
    @IBOutlet weak var btnGoogleSignIn: UIButton!
    @IBOutlet weak var btnLoad: UIButton!
    @IBOutlet weak var txtPass: UITextField!

    @IBOutlet weak var btnSave: UIButton!
    @IBOutlet weak var swSavePass: UISwitch!
    
    @IBOutlet weak var txtSource: UITextView!
    
    @IBAction func doSignIn(_ sender: UIButton) {
        GIDSignIn.sharedInstance().signIn()
    }
    @IBAction func doDecrypt(_ sender: UIButton) {
        let ae = AESEncryption();
        let decData:Data?;
        let sourceData:Data? = Data(base64Encoded: txtSource.text)
        let passData:Data? = txtPass.text?.data(using: .utf8)
        if sourceData == nil {
            showAlert(title: FILENAME, message: "Error decoding source data!!")
            return;
        }
        if passData == nil {
            showAlert(title: FILENAME, message: "Error parsing password value!!")
            return;
        }
        do{
            decData = try ae.aesCBCDecrypt(data: sourceData!, keyDataP: passData!)
            if decData != nil{
                txtSource.text = String(data: decData!, encoding: .utf8);
            }else{
                showAlert(title: FILENAME, message: "Error decoding source data!")
                return;
            }
        }catch let error{
            showAlert(title: FILENAME, message: error.localizedDescription)
        }
    }

    @IBAction func doEncrypt(_ sender: UIButton) {
        let ae = AESEncryption();
        let encData:Data;
        do{
            encData = try ae.aesCBCEncrypt(data: (txtSource.text?.data(using: String.Encoding.utf8))!, keyDataP: (txtPass.text?.data(using: String.Encoding.utf8))!);
            
            txtSource.text = encData.base64EncodedString()
            
        }catch let error{
            showAlert(title: "Error", message: error.localizedDescription)
        }
    }
    
    @IBAction func toggleSavePass(_ sender: UISwitch) {
        let defaults = UserDefaults.standard
        defaults.set(sender.isOn, forKey:"savePass")
        if sender.isOn{
            defaults.set(txtPass.text ?? "", forKey: "userPass")
        }else{
            defaults.removeObject(forKey: "userPass")
        }
        defaults.synchronize()
    }
    
    func dismissKeyboard(){
        view.endEditing(true)
    }
    
    @IBAction func saveFile(_ sender: UIButton) {
        wait = showWait(title: "Saving file", message: "Querying for file")
        present(wait!, animated: true, completion: nil)
        let query = GTLRDriveQuery_FilesList.query()
        query.pageSize = 10
        query.q = "name='\(FILENAME)' and trashed=false and mimeType='\(MIMETYPE)'"
        service.executeQuery(query,
                             delegate: self,
                             didFinish: #selector(saveFileContents(ticket:finishedWithObject:error:))
        )
    }
    
    @IBAction func loadFile(_ sender: UIButton) {
        wait = showWait(title: "Loading file", message: "Querying for file")
        present(wait!, animated: true, completion: nil)
        let query = GTLRDriveQuery_FilesList.query()
        query.pageSize = 10
        query.q = "name='\(FILENAME)' and trashed=false and mimeType='\(MIMETYPE)'"
        service.executeQuery(query,
                             delegate: self,
                             didFinish: #selector(loadFileContents(ticket:finishedWithObject:error:))
        )
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        let tap: UITapGestureRecognizer = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
        tap.cancelsTouchesInView = false
        
        view.addGestureRecognizer(tap)
        let defaults = UserDefaults.standard
        swSavePass.setOn(defaults.bool(forKey: "savePass"), animated: true)
        if swSavePass.isOn{
            txtPass.text = defaults.string(forKey:"userPass") ?? ""
        }
        GIDSignIn.sharedInstance().delegate = self
        GIDSignIn.sharedInstance().uiDelegate = self
        GIDSignIn.sharedInstance().scopes = scopes
        GIDSignIn.sharedInstance().clientID = "11399004738-a6qb082kcvh6h1afkbusoaue3r6mmsbj.apps.googleusercontent.com"
        GIDSignIn.sharedInstance().signInSilently()
        btnLoad.isHidden=true;
        btnSave.isHidden=true;
        // Add the sign-in button.
        
        //view.addSubview(signInButton)
    }
    func sign(_ signIn: GIDSignIn!, didSignInFor user: GIDGoogleUser!,
              withError error: Error!) {
        if let error = error {
            showAlert(title: "Authentication Error", message: error.localizedDescription)
            self.service.authorizer = nil
        } else {
            //self.signInButton.isHidden = true
            //self.output.isHidden = false
            btnGoogleSignIn.isHidden=true;
            btnLoad.isHidden=false;
            btnSave.isHidden=false;
            self.service.authorizer = user.authentication.fetcherAuthorizer()
            //listFiles()
        }
    }
    
    // Process the response and display output
    func saveFileContents(ticket: GTLRServiceTicket,
                                 finishedWithObject result : GTLRDrive_FileList,
                                 error : NSError?) {
        if let error = error {
            showAlert(title: "Error", message: error.localizedFailureReason!)
            return
        }
        wait?.message = "Saving file"
        let dataToSave:Data = (txtSource.text?.data(using: String.Encoding.utf8))!
        var file: GTLRDrive_File
        let uploadParams = GTLRUploadParameters.init(data: dataToSave, mimeType: MIMETYPE)
        var query: GTLRDriveQuery
//        let fieldList = "id,name,modifiedTime,mimeType"
//        GTMSessionFetcher.setLoggingEnabled(true)
        if let foundFiles = result.files?.count{
            if(foundFiles>0){
                let fileid: String = result.files![0].identifier!
                file = GTLRDrive_File.init()
                query = GTLRDriveQuery_FilesUpdate.query(withObject: file, fileId: fileid, uploadParameters: uploadParams)
            }else{
                file = GTLRDrive_File.init()
                file.name = FILENAME
                file.mimeType = MIMETYPE
                query = GTLRDriveQuery_FilesCreate.query(withObject: file, uploadParameters: uploadParams)
            }
            //debugPrint("File found -> Name = \(file.name!) with Id : \(file.identifier!)")
        }else{
            file = GTLRDrive_File.init()
            file.name = FILENAME
            file.mimeType = MIMETYPE
            query = GTLRDriveQuery_FilesCreate.query(withObject: file, uploadParameters: uploadParams)
        }
        service.executeQuery(query, completionHandler: {(ticket:GTLRServiceTicket!, finishedWithObject: Any?, error: Error?)-> Void in
            if let error = error{
                self.wait?.dismiss(animated: true, completion: nil)
                self.showAlert(title: "Error", message: error.localizedDescription)
                return
            }
            self.wait?.dismiss(animated: true, completion: nil)
            self.showAlert(title: self.FILENAME, message: "Data saved successfully!")
        })
    
    }
    
    // Process the response and display output
    func loadFileContents(ticket: GTLRServiceTicket,
                          finishedWithObject result : GTLRDrive_FileList,
                          error : NSError?) {
        if let error = error {
            wait?.dismiss(animated: true, completion: nil)
            showAlert(title: "Error", message: error.localizedFailureReason!)
            return
        }
        wait?.message = "Opening file"
        var file: GTLRDrive_File
        if let files = result.files{
            if files.count>0 {
                file = files[0]
            }else{
                wait?.dismiss(animated: true, completion: nil)
                showAlert(title: "Error", message: "Unable to get file handle")
                return
            }
            let query = GTLRDriveQuery_FilesGet.queryForMedia(withFileId: file.identifier!)
            service.executeQuery(query, completionHandler: {(ticket:GTLRServiceTicket!, finishedWithObject: Any?, error: Error?)-> Void in
                if let error = error{
                    self.wait?.dismiss(animated: true, completion: nil)
                    self.showAlert(title: "Error", message: error.localizedDescription)
                    return
                }
                var fileData: String
                let result: GTLRDataObject = finishedWithObject as! GTLRDataObject
                fileData = String(data: result.data, encoding: String.Encoding.utf8)!
                if let r = fileData.range(of: "\n"){
                    fileData.removeSubrange(r)
                }
                self.txtSource.text = fileData
                self.wait?.dismiss(animated: true, completion: nil)
            })
        }else{
            wait?.dismiss(animated: true, completion: nil)
            showAlert(title: "Error", message: "File not found!")
        }
    }
    
    
    // Helper for showing an alert
    func showAlert(title : String, message: String) {
        let alert = UIAlertController(
            title: title,
            message: message,
            preferredStyle: UIAlertControllerStyle.alert
        )
        let ok = UIAlertAction(
            title: "OK",
            style: UIAlertActionStyle.default,
            handler: nil
        )
        alert.addAction(ok)
        present(alert, animated: true, completion: nil)
    }
    
    func showWait(title: String, message: String) -> UIAlertController{
        let alert = UIAlertController(
            title: title,
            message: message,
            preferredStyle: UIAlertControllerStyle.actionSheet
        )
        return alert
    }
    
}
