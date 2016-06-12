class SaltyBrowser:
    def __init__(self, page):
        self.page = page
        self.saltyCrypto = SaltyCrypto()

    def processDivs(self):
        self.saltyDivs = page.mainFrame().findAllElements("DIV.saltyStele")
        for div in self.saltyDivs:
            processDiv(div)

    def processDiv(self, div):
        if div.hasAttribute("type"):
            divType = div.attribute("type")
            if divType == "EncryptedMessage" or divType == "EncryptedGroupMessage" or divType == "SignedMessage":
                signee = saltyCrypto.verifyDIV(div)
            if divType == "EncryptedMessage":
                msg = saltyCrypto.decryptDIV(div)
            elif divType == "EncryptedGroupMessage":
                msg = saltyCrypto.decryptGroupDIV(div)
            elif divType != "SignedMessage":
                print("unknown type", divType)
        else:
            print("has no type")

class SaltyCrypto:
    def decryptDIV(self, div):
        return keybase.decrypt(div.toPlainText())


    def decryptGroupDIV(self, div):
        import AES
        if div.hasAttribute("encryptedKey"):
            encryptedKey = div.attribute("encryptedKey")
            encryptedKeySignature = div.attribute("encryptedKeySignature")
            keySignee = keybase.verify(encryptedKey, encryptedKeySignature)
            aesKey = keybase.decrypt(encryptedKey)
            aesD = AESDecryptor(aesKey)
            encryptedMessage = aesD.decrypt(div.toPlainText())
        else:
            print("no encrypted key found")

    def verifyDIV(self, div):
        msg = div.toPlainText()
        if div.hasAttribute("signature"):
            signee = keybase.verify(msg, div.attribute("signature"))
        else:
            if "SIGNED" in msg:
                signee = keybase.verify(msg)
            else:
                signee = "Not signed by anyone"
        return signee

class keybaseHelper:
    import subprocess
    def decrypt(self, msg):
        return subprocess.call('keybase decrypt -m "' + msg + '"')

    def verify(self, msg):
        return subprocess.call('keybase verify -m "' + msg + '"')

    def verify(self, msg, signature):
        import tempfile
        #write signature into temporary file
        tFile = tempFile.NamedTemporaryFile(delete=False)
        tFile.write(signature)
        tFile.close
        result = subprocess.call('keybase verify -m "' + msg + '" -d "' + tFile.name + '"')
        os.unlink(tFile.name)
        return result

