import subprocess
import tempfile
import os
class SaltyBrowser:
    def __init__(self, page):
        self.page = page
        self.saltyCrypto = SaltyCrypto()

    def processDivs(self):
        self.saltyDivs = self.page.mainFrame().findAllElements("DIV.saltyStele")
        for div in self.saltyDivs:
            self.processDiv(div)

    def processDiv(self, div):
        msg = ""
        if div.hasAttribute("type"):
            divType = div.attribute("type")
            if divType == "EncryptedMessage" or divType == "EncryptedGroupMessage" or divType == "SignedMessage":
                signee = self.saltyCrypto.verifyDIV(div)
            if divType == "EncryptedMessage":
                msg = self.saltyCrypto.decryptDIV(div)
            elif divType == "EncryptedGroupMessage":
                msg = self.saltyCrypto.decryptGroupDIV(div)
            elif divType != "SignedMessage":
                print("unknown type", divType)
            if len(msg) == 0:
                div.setPlainText(str(div.toPlainText()) + " signed by " + signee)
            else:
                div.setPlainText(msg + " signed by " + signee)
        else:
            print("has no type")

class SaltyCrypto:
    def __init__(self):
        self.keybase = KeybaseHelper()
    def decryptDIV(self, div):
        return self.keybase.decrypt(div.toPlainText())

    def decryptGroupDIV(self, div):
        import AES
        if div.hasAttribute("encryptedKey"):
            encryptedKey = div.attribute("encryptedKey")
            encryptedKeySignature = div.attribute("encryptedKeySignature")
            keySignee = self.keybase.verify(encryptedKey, encryptedKeySignature)
            aesKey = self.keybase.decrypt(encryptedKey)
            aesD = AESDecryptor(aesKey)
            encryptedMessage = aesD.decrypt(div.toPlainText())
        else:
            print("no encrypted key found")

    def verifyDIV(self, div):
        msg = div.toPlainText()
        if div.hasAttribute("signature"):
            signature = div.attribute("signature")
            signee = self.keybase.verify(msg, signature)
        else:
            if "SIGNED" in msg:
                signee = self.keybase.verify(msg)
            else:
                signee = "Not signed by anyone"
        return signee

class KeybaseHelper:
    def decrypt(self, msg):
        try:
            result = subprocess.check_output('keybase decrypt -m "' + str(msg) + '"', shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            result = err.output
        return result

    def verify(self, msg):
        try:
            result = subprocess.check_output('keybase verify -m "' + str(msg) + '"', shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            result = err.output
        return result

    def verify(self, msg, signature):
        #write signature into temporary file
        tFile = tempfile.NamedTemporaryFile(mode="w+t", delete=False)
        tFile.write(signature)
        tFile.close()
        try:
            result = subprocess.check_output('keybase verify -m "' + str(msg) + '" -d "' + tFile.name + '"', shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            result = err.output
        os.unlink(tFile.name)
        return result

