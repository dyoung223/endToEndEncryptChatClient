'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = null // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    const keypairObject = await generateEG()
    this.EGKeyPair = keypairObject

    const certificate = {
      "username" : username,
      "pub" : keypairObject.pub
    }
    
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    let valid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (valid) {
      this.certs[certificate.username] = certificate
    }
    else{
      throw ('Tampered certificate!')
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage (name, plaintext) {


    let cert = this.certs[name]
     
    if(!(name in this.certs) ){

      let rootkey = await computeDH(this.EGKeyPair.sec, cert.pub) 
      let keypair = await generateEG()
      let computedDH = await computeDH(keypair.sec, cert.pub) 
      var [next_root, send_root] = await HKDF(rootkey, computedDH, "ratchet-str")
      var [send_root, message_key] = await HKDF(send_root, 0, "ratchet-str")
      let AES_key = await HMACtoHMACKey(message_key, "hello")
      let HMAC_key = await HMACtoAESKey(send_root, "hi")
      
    let connState = {
      keypair : keypair,
      next_root : next_root,
      recv_root : null,
      send_root : send_root
    }    
      this.certs[name] = connState
    }
    
    

    //let salt = genRandomSalt()
    

    let sendingChainKeyArr = HKDF(computedDH, rootKey, "ratchet-str")
    let newSalt = sendingChainKeyArr[0] //this.RootKey
    let sendChainKey = sendingChainKeyArr[1]
    


    const header = {
        pub : this.EGKeyPair.pub,
        salt : salt
    }
    const ciphertext = ''


    
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    throw ('not implemented!')
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
