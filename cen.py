from gi.repository import Gtk, Gdk
import hmac, hashlib
import os, binascii
import gnupg
from Crypto.Cipher import AES, DES3, ARC4
from Crypto.Hash import SHA
from Crypto import Random

fName = ""
docVar = "Untitled"
labelText = Gtk.Label("Working in Document: " + docVar)
labelFileName = Gtk.Label(fName)
#isNew = true if the new document haven't a name yet
isNew = 1
#isSigned = true if the document is signed
isSigned = False
decWith = ""
encWith = ""

###############################################################################################
#Encription/Decription Functions
def Generate_Key(size):
    random_key = os.urandom(size)
    return random_key

def make_digest(key, message):
    "Return a digest for the message."
    return hmac.new(key, message, hashlib.sha1).hexdigest()

def encrypt(key, message, cipher):
    if cipher == 1: #AES 
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CTR, iv, counter=lambda: iv)
        msg = iv + cipher.encrypt(message)
        return msg.encode("base64")
    if cipher == 2:  #3DES
        iv = Random.new().read(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_CTR, iv, counter=lambda: iv)
        msg = iv + cipher.encrypt(message)
        return msg.encode("base64")
    else:   #RC4
        iv = Random.new().read(16)
        tempkey = SHA.new(key+iv).digest()
        cipher = ARC4.new(tempkey)
        msg = iv + cipher.encrypt(message)
        return msg.encode("base64")

#Faz a decifragem de um ficheiro, totalmente ou apenas parcialmente
def decrypt(key, enc, et, sp, sf):
    global encWith
    if et == "A":
        encWith = 1
        iv = enc[:16]
        cipher = AES.new(key, AES.MODE_CTR, iv, counter=lambda: iv)
        enc = enc[16:]
        sp = int (sp/16)
        sf = int (sf/16)
        return (cipher.decrypt( enc[sp*16:sf*16] ))
    if et == "D":
        encWith = 2
        iv = enc[:8]
        cipher = DES3.new(key, DES3.MODE_CTR, iv, counter=lambda: iv)
        enc = enc[8:]
        sp = int (sp/8)
        sf = int (sf/8)
        return (cipher.decrypt( enc[sp*8:sf*8] ))
    if et == "R":
        encWith = 3
        iv = enc[:16]
        tempkey = SHA.new(key+iv).digest()
        cipher = ARC4.new(tempkey)
        enc = enc[16:]
        return (cipher.decrypt(enc))

#Save Key and Hmac in File
def Save_keys(bin_key, hmac, ct, path):
    armor_key = bin_key.encode("base64")    
    fkey = open(path + "keys_and_iv.txt", "w")
    textkey = ct+" ----- KEY BLOCK -----\n"+armor_key+"----- HMAC BLOCK -----\n"+hmac+"\n----- END BLOCK -----"
    fkey.write(textkey)
    fkey.close()

#Read keys from file
def Read_keys(path):
    try:
        fkey = open(path+"/keys_and_iv.txt", "r")
    except IOError:
        return False, False, False
    ct = fkey.read(1)
    first_line = fkey.readline()
    full_file = fkey.read()
    keyend = full_file.find("----- HMAC BLOCK -----\n")
    macend = full_file.find("\n----- END BLOCK -----")
    armor_key = full_file[:keyend]
    hmac = full_file[keyend+23:macend]
    fkey.close()
    return (binascii.a2b_base64(armor_key)), hmac, ct

# Sign / Verify File
def generate_key(gpg, first_name, last_name, domain, passphrase=None):
    "Generate a key"
    params = {
        'Key-Type': 'RSA',
        'Key-Length': 1024,
        'Subkey-Type': 'RSA',
        'Subkey-Length': 1024,
        'Name-Comment': 'SecuriText User',
        'Expire-Date': 0,
    }
    params['Name-Real'] = '%s %s' % (first_name, last_name)
    params['Name-Email'] = ("%s.%s@%s" % (first_name, last_name, domain)).lower()
    if passphrase is None:
        passphrase = ("%s%s" % (first_name[0], last_name)).lower()
    params['Passphrase'] = passphrase
    cmd = gpg.gen_key_input(**params)
    return gpg.gen_key(cmd)

def Signature_Check(docVar):
    direc = docVar+"signature.sign"
    return (os.path.isfile(direc))

def Signature_Verify(docVar,fName):
    gpg = gnupg.GPG(gnupghome="keys/.gnupg")
    #Verificar se um ficheiro foi assinado
    try:
        fkey = open(docVar+"chavepublica.pem", "r")
    except IOError:
        print "ChavePublicaNotFound!"
        return
    import_result = gpg.import_keys(fkey.read())
    verified = gpg.verify_file(open(docVar+"signature.sign"),fName)
    return verified

##############################################################################################
#GUI functions
class OpenDialog(Gtk.Dialog):

    def __init__(self, parent):
        global fName
        fName = ""
        Gtk.Dialog.__init__(self, "Open", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_OPEN, Gtk.ResponseType.OK,
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))

        box = self.get_content_area()

        label1 = Gtk.Label("\nChoose a File to open:\n Make sure that respective \"keys_and_iv.txt\" \n is on same folder: \n")
        box.add(label1)

        button1 = Gtk.Button("Choose File")
        button1.connect("clicked", self.on_file_clicked)
        box.add(button1)

        box.add(labelFileName)

        self.label0 = Gtk.Label("\n Decrypt Part of File?")
        box.add(self.label0)
        
        self.switch = Gtk.Switch()
        self.switch.connect("notify::active", self.on_switch_activated)
        self.switch.set_active(False)
        box.add(self.switch)
        
        self.label1 = Gtk.Label("\nStarting Caracter:")
        box.add(self.label1)
        self.spin1 = Gtk.SpinButton()
        self.spin1.set_adjustment(Gtk.Adjustment(0, 0, 100, 1, 10, 0))
        box.add(self.spin1)

        self.label2 = Gtk.Label("\nFinal Caracter:")
        box.add(self.label2)
        self.spin2 = Gtk.SpinButton()
        self.spin2.set_adjustment(Gtk.Adjustment(0, 0, 100, 1, 10, 0))
        box.add(self.spin2)

        self.show_all()
        self.switch.hide()
        self.label0.hide()
        self.spin1.hide()
        self.label1.hide()
        self.spin2.hide()
        self.label2.hide()
    
    def on_switch_activated(self, switch, gparam):
        if switch.get_active():
            state = "on"
            self.spin1.show()
            self.label1.show()
            self.spin2.show()
            self.label2.show()
        else:
            state = "off"
            self.spin1.hide()
            self.label1.hide()
            self.spin2.hide()
            self.label2.hide()

    def on_dec_combo_changed(self, combo):
        global decWith
        tree_iter = combo.get_active_iter()
        if tree_iter != None:
            model = combo.get_model()
            row_id, name = model[tree_iter][:2]
            decWith = row_id

    def on_file_clicked(self, widget):
        global labelFileName
        global fName
        dialog = Gtk.FileChooserDialog("Please choose a file", self,
            Gtk.FileChooserAction.OPEN,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        #self.add_filters(dialog)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            labelFileName.set_label(dialog.get_filename())
            fName = dialog.get_filename()
            sf = len(open(fName).read())
            self.spin1.set_adjustment(Gtk.Adjustment(0, 0, sf, 1, 10, 0))
            self.spin2.set_adjustment(Gtk.Adjustment(0, 0, sf, 1, 10, 0))
            self.spin2.set_value(sf)
            self.label0.show()
            self.switch.show()
        elif response == Gtk.ResponseType.CANCEL:
            dialog.destroy()

        dialog.destroy()

#########################

class Certificate(Gtk.Dialog):

    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "Certificate Generation", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_OK, Gtk.ResponseType.OK,
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))
    
        box = self.get_content_area()
        
        label = Gtk.Label("We need some data:")
        box.add(label)

        label1 = Gtk.Label("\nFirst Name:")
        box.add(label1)
        self.FName = Gtk.Entry()
        box.add(self.FName)
  
        label2 = Gtk.Label("\nLast Name:")
        box.add(label2)
        self.LName = Gtk.Entry()
        box.add(self.LName)

        label4 = Gtk.Label("\nDomain:")
        box.add(label4)
        self.Domain = Gtk.Entry()
        box.add(self.Domain)
        
        
        label3 = Gtk.Label("\nPassword:")
        box.add(label3)
        self.Password = Gtk.Entry()
        self.Password.set_invisible_char("*")
        box.add(self.Password)



        self.show_all()

class HelpDialog(Gtk.Dialog):

    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "HELP", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))


        self.set_default_size(200, 250)
        self.set_border_width(10)

        box = self.get_content_area()

        label = Gtk.Label("SECURITEXT HELP\n")
        box.add(label)

        buttonSave = Gtk.Button("Save")
        buttonSave.connect("clicked", self.on_save_clicked)
        box.add(buttonSave)
     
        buttonSaveAs = Gtk.Button("Save As")
        buttonSaveAs.connect("clicked", self.on_saveas_clicked)
        box.add(buttonSaveAs)
        
        buttonOpen = Gtk.Button("Open")
        buttonOpen.connect("clicked", self.on_open_clicked)
        box.add(buttonOpen)
        
        buttonSign = Gtk.Button("Sign")
        buttonSign.connect("clicked", self.on_sign_clicked)
        box.add(buttonSign)
        
        buttonCert = Gtk.Button("Certificate")
        buttonCert.connect("clicked", self.on_cert_clicked)
        box.add(buttonCert)

        buttonCertList = Gtk.Button("Certificate list")
        buttonCertList.connect("clicked", self.on_certlist_clicked)
        box.add(buttonCertList)

        label3 = Gtk.Label("\n")
        box.add(label3)
        
        self.show_all()
        
    def on_save_clicked(self, combo):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
            Gtk.ButtonsType.OK, "Save - help")
        dialog.format_secondary_text(
            " If is the first time that you are saving a file it does the same as the button Save As. Else it saves the work with the same properties.")
        dialog.run()
        dialog.destroy()
        
    def on_saveas_clicked(self, combo):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
            Gtk.ButtonsType.OK, "Save As  - Help")
        dialog.format_secondary_text(
            " This button allows you to save a document safely, you can choose three cipher algorithms: 3Des, Aes and RC4. It also creates a file with the key and the iv used to do the encrypt. Put that file in a safe place.")
        dialog.run()
        dialog.destroy()

    def on_open_clicked(self, combo):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
            Gtk.ButtonsType.OK, "Save - Help")
        dialog.format_secondary_text(
            " Click here if you want to open a existing file. Here you can choice if you want to decipher the full file or just a part of it. To do this we ask you for the position of first caracter to the last caracter you want.")
        dialog.run()
        dialog.destroy()
        
    def on_sign_clicked(self, combo):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
            Gtk.ButtonsType.OK, "Sign - Help")
        dialog.format_secondary_text(
            "Signs the document with your private key.")
        dialog.run()
        dialog.destroy()
        
    def on_cert_clicked(self, combo):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
            Gtk.ButtonsType.OK, "New Certificate - Help")
        dialog.format_secondary_text(
            " Here you can create a new certificate, it creates a private and a public key.")
        dialog.run()
        dialog.destroy()        
        
    def on_certlist_clicked(self, combo):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
            Gtk.ButtonsType.OK, "Certificate lists  - Help")
        dialog.format_secondary_text(
            "This lists all the certificates.")
        dialog.run()
        dialog.destroy()        
        
        
class CertificateDialog(Gtk.Dialog):

    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "Certificate Dialog", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))

        gpg = gnupg.GPG(gnupghome="keys/.gnupg")

        box = self.get_content_area()

        label = Gtk.Label("Public keys listed in your key ring!\n")
        box.add(label)

        self.set_default_size(200, 400)

        self.liststore = Gtk.ListStore(str, str)

        public_keys = gpg.list_keys()
        for keys in public_keys:
            self.liststore.append([str(keys['uids'][0]),str(keys['keyid'])])


        treeview = Gtk.TreeView(model=self.liststore)

        renderer_text = Gtk.CellRendererText()
        column_text = Gtk.TreeViewColumn("Name", renderer_text, text=0)
        treeview.append_column(column_text)

        renderer_text2 = Gtk.CellRendererText()

        column_text2 = Gtk.TreeViewColumn("Public Key ID",renderer_text2, text=1)
        treeview.append_column(column_text2)

        scrolled_window = Gtk.ScrolledWindow()


        scrolled_window.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
      
        self.vbox.pack_start(scrolled_window, True, True, 0)
        scrolled_window.show()
          
              # create a table of 10 by 10 squares.
        table = Gtk.Table(10, 10, False)
      
              # set the spacing to 10 on x and 10 on y
        table.set_row_spacings(10)
        table.set_col_spacings(10)
      
              # pack the table into the scrolled window
        scrolled_window.add_with_viewport(treeview)
        table.show()

        box.add(treeview)

        self.show_all()
     
class InforDialog(Gtk.Dialog):

    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "INFO", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))

        box = self.get_content_area()

        label = Gtk.Label("SECURITEXT\n")
        box.add(label)

        image = Gtk.Image()
        image.set_from_file("securitext.png")
        image.show()
        box.add(image)

        label1 = Gtk.Label("\nThe Most Resilient Text Editor in Covilha\n\n")
        box.add(label1)
        label2 = Gtk.Label("Created by:\n")
        box.add(label2)
        label3 = Gtk.Label("Cristiano Ramos")
        box.add(label3)
        label4 = Gtk.Label("Micael Grilo")
        box.add(label4)
        label5 = Gtk.Label("Pedro Pinto")
        box.add(label5)
        label6 = Gtk.Label("Tiago Bernardo")
        box.add(label6)

        labelNewLine = Gtk.Label("\n\n")
        box.add(labelNewLine)


        self.show_all()

class WarningDialog(Gtk.Dialog):

    def __init__(self, parent, flag):
        Gtk.Dialog.__init__(self, "INFO:", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_OK, Gtk.ResponseType.OK))

        box = self.get_content_area()
        if flag:
            label = Gtk.Label('FILE OK : No data corruption!')
        else:
            label = Gtk.Label('WARNING: Data corruption!')
        box.add(label)

        self.show_all()
        self.show_all()

class InfoDialog(Gtk.Dialog):
    def __init__(self, parent, flag):
        Gtk.Dialog.__init__(self, "INFO:", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_OK, Gtk.ResponseType.OK))

        box = self.get_content_area()
        if flag:
            label = Gtk.Label('ATENTION: The file "keys_and_iv.txt" contains secret key to decrypt file!\nIt is stored on same folder!')
        else:
            label = Gtk.Label('ERROR: "keys_and_iv.txt" Nor Found!')
        box.add(label)

        self.show_all()

class SignatureDialog(Gtk.Dialog):
    def __init__(self, parent, verified):
        global isSigned
        Gtk.Dialog.__init__(self, "INFO:", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_OK, Gtk.ResponseType.OK))

        box = self.get_content_area()
        if verified:
            isSigned = True
            Message = "Valid Signature!\n" + "User Name: " + verified.username + "\nKey id: " + verified.key_id + "\nTrust Level: " + verified.trust_text + "\n"
        else:
            isSigned = False
            Message = "Invalid Signature!"
        label = Gtk.Label(Message)
        box.add(label)

        self.show_all()    

class InputDialog(Gtk.Dialog):
    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "SIGN:", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_OK, Gtk.ResponseType.OK,
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))
        gpg = gnupg.GPG(gnupghome="keys/.gnupg")

        box = self.get_content_area()
        label = Gtk.Label("Choose a certificate to sign the file!")
        box.add(label)

        self.keyid = ""
        self.keylist = {}
        name_store = Gtk.ListStore(str)
        private_keys = gpg.list_keys(True)
        for keys in private_keys:
            name_store.append([str(keys['uids'][0])])
            self.keylist[str(keys['uids'][0])] = str(keys['keyid'])

        name_combo = Gtk.ComboBox.new_with_model(name_store)
        name_combo.connect("changed", self.on_name_combo_changed)
        renderer_text = Gtk.CellRendererText()
        name_combo.set_active(0)
        name_combo.pack_start(renderer_text, True)
        name_combo.add_attribute(renderer_text, "text", 0)

        box.add(name_combo)

        label = Gtk.Label('Insert password of certificate to sign File!\n')
        box.add(label)
        self.password = Gtk.Entry()
        self.password.set_visibility(False)
        box.add(self.password)
        if len(self.keylist) == 0:
            label = Gtk.Label("No certificates available in keyrings,\nplease create a certificate first!")
            box.add(label)
            label.show()
        else:
            self.show_all()

    def on_name_combo_changed(self, combo):
        tree_iter = combo.get_active_iter()
        if tree_iter != None:
            model = combo.get_model()
            name = model[tree_iter][0]
            self.keyid =self.keylist[name]

class ErrorDialog(Gtk.Dialog):
    def __init__(self, parent, error):
        Gtk.Dialog.__init__(self, "INFO:", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_OK, Gtk.ResponseType.OK))

        box = self.get_content_area()
        label = Gtk.Label(error)
        box.add(label)

        self.show_all()

class SaveDialog(Gtk.Dialog):

    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "SAVE", parent,
            Gtk.DialogFlags.MODAL, buttons=(
            Gtk.STOCK_SAVE, Gtk.ResponseType.OK,
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))

        box = self.get_content_area()

        label = Gtk.Label("Saving your file as:\n")
        box.add(label)

        dialog = Gtk.FileChooserDialog("Save File:", None,
            Gtk.FileChooserAction.SAVE,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_SAVE, Gtk.ResponseType.OK))

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            fullpath = dialog.get_filename()
            dialog.destroy()
            fname = os.path.basename(fullpath)
            dirname = fname.split(".")[0]
            path = os.path.dirname(fullpath)

            self.path = path+"/"+dirname+"/"
            self.name = fname

            label1 = Gtk.Label(self.path+fname)
            box.add(label1)

            label2 = Gtk.Label("\nEncrypt with:\n")
            box.add(label2)


            enc_store = Gtk.ListStore(int, str)
            enc_store.append([1, "AES"])
            enc_store.append([2, "3DES"])
            enc_store.append([3, "RC4"])

            vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

            enc_combo = Gtk.ComboBox.new_with_model_and_entry(enc_store)
            enc_combo.connect("changed", self.on_enc_combo_changed)
            enc_combo.set_entry_text_column(1)
            enc_combo.set_active(0)
            vbox.pack_start(enc_combo, False, False, 0)

            box.add(vbox)


            labelNewLine = Gtk.Label("\n\n")
            box.add(labelNewLine)

            self.show_all()

        elif response == Gtk.ResponseType.CANCEL:
            dialog.destroy()
            return Gtk.ResponseType.CANCEL

    def on_enc_combo_changed(self, combo):
        global encWith
        tree_iter = combo.get_active_iter()
        if tree_iter != None:
            model = combo.get_model()
            row_id, name = model[tree_iter][:2]
            encWith = row_id
            #print encWith

class TextViewWindow(Gtk.Window):

    def __init__(self):
        Gtk.Window.__init__(self, title="SecuriText")

        self.set_default_size(1000, 700)

        self.grid = Gtk.Grid() 
        self.add(self.grid)


        self.create_textview()
        self.create_toolbar()
        self.create_status()

    def create_toolbar(self):
        toolbar = Gtk.Toolbar()
        #context = toolbar.get_style_context()
        #context.add_class(Gtk.STYLE_CLASS_PRIMARY_TOOLBAR)
        self.grid.attach(toolbar, 0, 0, 3, 1)

        button_new = Gtk.ToolButton.new_from_stock(Gtk.STOCK_NEW)
        button_new.set_is_important(True)
        button_new.connect("clicked", self.on_new_clicked)
        toolbar.insert(button_new, 0)

        button_save = Gtk.ToolButton.new_from_stock(Gtk.STOCK_SAVE)
        button_save.set_is_important(True)
        button_save.connect("clicked", self.on_save_clicked)
        toolbar.insert(button_save, 1)

        button_saveAS = Gtk.ToolButton.new_from_stock(Gtk.STOCK_SAVE_AS)
        button_saveAS.set_is_important(True)
        button_saveAS.connect("clicked", self.on_saveAS_clicked)
        toolbar.insert(button_saveAS, 2)

        button_open = Gtk.ToolButton.new_from_stock(Gtk.STOCK_OPEN)
        button_open.set_is_important(True)
        button_open.connect("clicked", self.on_open_clicked)
        toolbar.insert(button_open, 3)

        toolbar.insert(Gtk.SeparatorToolItem(), 4)

        button_sign = Gtk.ToolButton.new_from_stock(Gtk.STOCK_EDIT)
        button_sign.set_is_important(True)
        button_sign.set_label("Sign")
        button_sign.connect("clicked", self.on_sign_clicked)
        toolbar.insert(button_sign, 5)

        toolbar.insert(Gtk.SeparatorToolItem(), 6)
        
        button_cert = Gtk.ToolButton.new_from_stock(Gtk.STOCK_DND)
        button_cert.set_is_important(True)
        button_cert.set_label("New Certificate")
        button_cert.connect("clicked", self.on_cert_clicked)
        toolbar.insert(button_cert, 7)

        toolbar.insert(Gtk.SeparatorToolItem(), 8)

        button_certificate = Gtk.ToolButton.new_from_stock(Gtk.STOCK_DND_MULTIPLE)
        button_certificate.set_is_important(True)
        button_certificate.set_label("Certificate List")
        button_certificate.connect("clicked", self.on_certificate_clicked)
        toolbar.insert(button_certificate, 9)

        toolbar.insert(Gtk.SeparatorToolItem(), 10)

        button_help = Gtk.ToolButton.new_from_stock(Gtk.STOCK_HELP)
        button_help.set_is_important(True)
        button_help.connect("clicked", self.on_help_clicked)
        toolbar.insert(button_help, 11)

        toolbar.insert(Gtk.SeparatorToolItem(), 12)

        button_info = Gtk.ToolButton.new_from_stock(Gtk.STOCK_INFO)
        button_info.set_is_important(True)
        button_info.set_label("Info")
        button_info.connect("clicked", self.on_info_clicked)
        toolbar.insert(button_info, 13)

    def create_textview(self):
        scrolledwindow = Gtk.ScrolledWindow()
        scrolledwindow.set_hexpand(True)
        scrolledwindow.set_vexpand(True)
        self.grid.attach(scrolledwindow, 0, 1, 3, 1)

        self.textview = Gtk.TextView()
        self.textbuffer = self.textview.get_buffer()
        self.textbuffer.set_text("Welcome to SecuriText, the most resilient text editor in Covilha!")
        self.textview.set_editable(False)
        scrolledwindow.add(self.textview)

        self.tag_found = self.textbuffer.create_tag("found",background="yellow")

    def create_status(self):

        self.grid.attach(labelText, 1, 2, 1, 5)
        self.override_background_color(Gtk.StateType.NORMAL, Gdk.RGBA(0.80,0.80,0.80,1.0))

    #new save open
    def on_new_clicked(self, widget):
        global isNew
        global isSigned
        self.textbuffer.set_text("")
        self.textview.set_editable(True)
        isNew = 1
        isSigned = False
        docVar = "Untitled"
        labelText.set_label("Working in Document: " + docVar)
        
    def on_save_clicked(self, widget):
        global isNew
        global docVar
        global encWith
        global fName

        if isNew == 1:
            try:
                dialog = SaveDialog(self)
            except TypeError:
                return
            response = dialog.run()
            if response == Gtk.ResponseType.OK:
                path = dialog.path
                fname = dialog.name
                docVar = path
                fName = docVar + fname
                labelText.set_label("Working in Document :" + fname)
                isNew = 0
                dialog.destroy()
            if response == Gtk.ResponseType.CANCEL: 
                dialog.destroy()
                return

        if not os.path.exists(docVar):
            os.makedirs(docVar)
        else:
            path = docVar
            fname = labelText.get_text().split(":")[1]

        if encWith == 1:
        #Save encripted text aes-256
            texto = self.textbuffer.get_text(self.textbuffer.get_start_iter(),self.textbuffer.get_end_iter(),True)
            key = Generate_Key(32) #32 byte key
            f = open(path+fname, "w")
            encrypted_message = encrypt(key,texto,1)
            ct = "A"
            f.write(encrypted_message)
            f.close()
        if encWith == 2:
        #Save encripted text 3DES
            texto = self.textbuffer.get_text(self.textbuffer.get_start_iter(),self.textbuffer.get_end_iter(),True)
            key = Generate_Key(16) #16 byte key
            f = open(path+fname, "w")
            encrypted_message = encrypt(key,texto,2)
            ct = "D"
            f.write(encrypted_message)
            f.close()
        if encWith == 3:
        #Save encripted text RC4
            texto = self.textbuffer.get_text(self.textbuffer.get_start_iter(),self.textbuffer.get_end_iter(),True)
            key = Generate_Key(256) #256 byte key
            f = open(path+fname, "w")
            encrypted_message = encrypt(key,texto,3)
            ct = "R"
            f.write(encrypted_message)
            f.close()
        #Save keys
        mac = make_digest(key, encrypted_message)
        Save_keys(key, mac, ct, path)
        info_dialog = InfoDialog(self, True)
        i_response = info_dialog.run()
        if i_response == Gtk.ResponseType.OK:
            info_dialog.destroy()
        #print "Alert! Key file has been generated!"

    def on_saveAS_clicked(self, widget):
        global isNew
        global docVar
        global encWith
        global fName
        try:
            dialog = SaveDialog(self)
        except TypeError:
            return
        response = dialog.run()
        #caso seja para gravar
        if response == Gtk.ResponseType.OK:
            path = dialog.path
            fname = dialog.name
            docVar = path
            fName = docVar + fname
            labelText.set_label("Working in Document :" + fname)
            isNew = 0
            dialog.destroy()
            if not os.path.exists(docVar):
                os.makedirs(docVar)
            if encWith == 1:
            #Save encripted text aes-256
                texto = self.textbuffer.get_text(self.textbuffer.get_start_iter(),self.textbuffer.get_end_iter(),True)
                key = Generate_Key(32) #32 byte key
                f = open(path+fname, "w")
                encrypted_message = encrypt(key,texto,1)
                ct = "A"
                f.write(encrypted_message)
                f.close()
            if encWith == 2:
            #Save encripted text 3DES
                texto = self.textbuffer.get_text(self.textbuffer.get_start_iter(),self.textbuffer.get_end_iter(),True)
                key = Generate_Key(16) #16 byte key
                f = open(path+fname, "w")
                encrypted_message = encrypt(key,texto,2)
                ct = "D"
                f.write(encrypted_message)
                f.close()
            if encWith == 3:
            #Save encripted text RC4
                texto = self.textbuffer.get_text(self.textbuffer.get_start_iter(),self.textbuffer.get_end_iter(),True)
                key = Generate_Key(256) #256 byte key
                f = open(path+fname, "w")
                encrypted_message = encrypt(key,texto,3)
                ct = "R"
                f.write(encrypted_message)
                f.close()
            #Save keys
            mac = make_digest(key, encrypted_message)
            Save_keys(key, mac, ct, path)
            info_dialog = InfoDialog(self, True)
            i_response = info_dialog.run()
            if i_response == Gtk.ResponseType.OK:
                info_dialog.destroy()
            #print "Alert! Key file has been generated!"
        if response == Gtk.ResponseType.CANCEL:
            dialog.destroy()

    def on_open_clicked(self, widget):
        global isNew
        global decWith
        global fName
        global docVar
        global labelFileName
        self.textview.set_editable(True)
        dialog = OpenDialog(self)
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            sp, sf = dialog.spin1.get_value(), dialog.spin2.get_value()
            docVar = os.path.dirname(fName) + "/"
            read_key, read_hmac , et = Read_keys(docVar)
            if read_key == False:
                signed = Signature_Check(docVar)
                if signed:
                    data = open(fName, 'r').read()
                    self.textbuffer.set_text(data)
                    dialog.destroy()
                    verified = Signature_Verify(docVar,fName)
                    sdialog = SignatureDialog(self,verified)
                    response = sdialog.run()
                    if response == Gtk.ResponseType.OK:
                        sdialog.destroy() 
                    return
                else:
                    info_dialog = InfoDialog(self, False)
                    i_response = info_dialog.run()
                    if i_response == Gtk.ResponseType.OK:
                        info_dialog.destroy()
                        dialog.destroy()
                    return
            self.textbuffer.set_text("")
            isNew = 0
            f = open(fName, 'r')
            encrypted_message = f.read()
            try:
                decrited = decrypt(read_key, binascii.a2b_base64(encrypted_message), et, sp, sf)
            except binascii.Error:
                dialog.destroy()
                info_dialog = WarningDialog(self,False)
                i_response = info_dialog.run()
                if i_response == Gtk.ResponseType.OK:
                    info_dialog.destroy()
                return

            self.textbuffer.set_text(decrited.decode('utf-8', 'ignore'))
            f.close()
            labelText.set_label("Working in Document :" + fName.split("/")[-1])
            signed = Signature_Check(docVar)
            if not signed:
                actual_mac = make_digest(read_key,encrypted_message)
                if read_hmac != actual_mac:
                    info_dialog = WarningDialog(self,False)
                    i_response = info_dialog.run()
                    if i_response == Gtk.ResponseType.OK:
                        info_dialog.destroy()
                else:
                    info_dialog = WarningDialog(self,True)
                    i_response = info_dialog.run()
                    if i_response == Gtk.ResponseType.OK:
                        info_dialog.destroy()
            else:
                verified = Signature_Verify(docVar,fName)
                sdialog = SignatureDialog(self,verified)
                response = sdialog.run()
                if response == Gtk.ResponseType.OK:
                    sdialog.destroy() 
        if response == Gtk.ResponseType.CANCEL:
            dialog.destroy()
        dialog.destroy()
        labelFileName.set_label("")

    def on_sign_clicked(self, widget):
        global fName
        global docVar
        global isNew
        global isSigned

        gpg = gnupg.GPG(gnupghome="keys/.gnupg")
        if isSigned:
            dialog2 = ErrorDialog(self, "File is already signed!")
            response = dialog2.run()
            dialog2.destroy()
            return
        if isNew is 1:
            #Se Novo Documento e e pedido para assinar guarda-mos o novo documento apenas assinado
            texto = self.textbuffer.get_text(self.textbuffer.get_start_iter(),self.textbuffer.get_end_iter(),True)
            dialog = Gtk.FileChooserDialog("Save File:", None,
                Gtk.FileChooserAction.SAVE,
                (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
            response = dialog.run()
            if response == Gtk.ResponseType.OK:
                fullpath = dialog.get_filename()
                dialog.destroy()
                fname = os.path.basename(fullpath)
                dirname = fname.split(".")[0]
                path = os.path.dirname(fullpath)
                path = path+"/"+dirname+"/"

                dialog = InputDialog(self)
                response = dialog.run()
                if response == Gtk.ResponseType.OK:
                    docVar = path
                    fName = docVar + fname
                    labelText.set_label("Working in Document :" + fname)
                    isNew = 0

                    if not os.path.exists(docVar):
                        os.makedirs(docVar)

                    f = open(path+fname, "w")
                    f.write(texto)
                    f.close()

                    password = dialog.password.get_text()
                    key = dialog.keyid
                    if key == "":
                        dialog.destroy()
                    elif password == "":
                        dialog2 = ErrorDialog(self, "Password Field is obrigatory!")
                        response = dialog2.run()
                        dialog2.destroy()
                    else:
                        data = open(path+fname,"r")
                        signed_data = gpg.sign_file(data, keyid = key, passphrase=password, detach=True)
                        if len(str(signed_data)) == 0:
                            dialog2 = ErrorDialog(self, "ERROR!\nInvalid PassWord!")
                            response = dialog2.run()
                            dialog2.destroy()
                        else:
                            f = open(docVar+"signature.sign", "w")
                            f.write(str(signed_data))
                            f.close()
                            ascii_armored_public_keys = gpg.export_keys(key)
                            fa = open(docVar+"chavepublica.pem", "w")
                            fa.write(ascii_armored_public_keys)
                            fa.close()
                            dialog2 = ErrorDialog(self, "SUCESS!\nFile Signature and Public Key have been added to:\n "+ docVar + " \n")
                            isSigned = True
                            response = dialog2.run()
                            dialog2.destroy()
                dialog.destroy()   
            else:
                dialog.destroy()
        else:
            dialog = InputDialog(self)
            response = dialog.run()
            if response == Gtk.ResponseType.OK:
                password = dialog.password.get_text()
                key = dialog.keyid
                if key == "":
                    dialog.destroy()
                elif password == "":
                    dialog2 = ErrorDialog(self, "Password Field is obrigatory!")
                    response = dialog2.run()
                    dialog2.destroy()
                else:
                    data = open(fName,"r")
                    signed_data = gpg.sign_file(data, keyid = key, passphrase=password, detach=True)
                    if len(str(signed_data)) == 0:
                        dialog2 = ErrorDialog(self, "ERROR!\nInvalid PassWord!")
                        response = dialog2.run()
                        dialog2.destroy()
                    else:
                        f = open(docVar+"signature.sign", "w")
                        f.write(str(signed_data))
                        f.close()
                        ascii_armored_public_keys = gpg.export_keys(key)
                        fa = open(docVar+"chavepublica.pem", "w")
                        fa.write(ascii_armored_public_keys)
                        fa.close()
                        dialog2 = ErrorDialog(self, "SUCESS!\nFile Signature and Public Key have been added to:\n "+ docVar + " \n")
                        isSigned = True
                        response = dialog2.run()
                        dialog2.destroy()
            dialog.destroy()

    def on_cert_clicked(self, widget):
        dialog = Certificate(self)
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            gpg = gnupg.GPG(gnupghome="keys/.gnupg")
            FNome = dialog.FName.get_text()
            LNome = dialog.LName.get_text()
            domain = dialog.Domain.get_text()
            Password = dialog.Password.get_text()
            if FNome == "" or LNome == "" or domain == "" or Password == "" :
                dialog2 = ErrorDialog(self, "ERROR! All fields are obrigatory!")
                response = dialog2.run()
                dialog2.destroy()
            else:
                key = generate_key(gpg, FNome, LNome, domain,passphrase=Password)
                dialog2 = ErrorDialog(self, "New Certificate For '%s %s' has been generated!" % (FNome, LNome))
                response = dialog2.run()
                dialog2.destroy()
        dialog.destroy()       
        
    def on_help_clicked(self, widget):
        dialog = HelpDialog(self)
        response = dialog.run()
        dialog.destroy()

    def on_info_clicked(self, widget):
        dialog = InforDialog(self)
        response = dialog.run()
        dialog.destroy()

    def on_certificate_clicked(self, widget):
        dialog = CertificateDialog(self)
        response = dialog.run()
        dialog.destroy()


win = TextViewWindow()
win.connect("delete-event", Gtk.main_quit)
win.show_all()
Gtk.main()
