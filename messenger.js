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
     
    if(!(name in this.conns) ){

      let rootkey = await computeDH(this.EGKeyPair.sec, cert.pub) 
      var keypair = await generateEG()
      let computedDH = await computeDH(keypair.sec, cert.pub) 
      var [next_root, send_root] = await HKDF(rootkey, computedDH, "ratchet-str")
      var AES_key = await HMACtoAESKey(send_root, "AES")
      send_root = await HMACtoHMACKey(send_root, "HMAC")
      
      let connState = {
        keypair : keypair,
        next_root : next_root,
        recv_root : null,
        send_root : send_root,
        recv_pub : cert.pub,
        curr_sender : true
      }    

      this.conns[name] = connState
    }
    else {
      let connState = this.conns[name]
      if (connState.curr_sender) {
        var AES_key = await HMACtoAESKey(connState.send_root, "AES")
        connState.send_root = await HMACtoHMACKey(connState.send_root, "HMAC")
        var keypair = connState.keypair
      }
      else {
        var keypair = await generateEG()
        let computedDH = await computeDH(keypair.sec, connState.recv_pub) 
        var [next_root, send_root] = await HKDF(connState.next_root, computedDH, "ratchet-str")
        var AES_key = await HMACtoAESKey(send_root, "AES")
        send_root = await HMACtoHMACKey(send_root, "HMAC")
        
        let connState = {
          keypair : keypair,
          next_root : next_root,
          recv_root : connState.recv_root,
          send_root : send_root,
          recv_pub : connState.recv_pub,
          curr_sender : true
        }    

        this.conns[name] = connState
      }
    }

    let ivGov = genRandomSalt()
    var govkeypair = await generateEG()
    let govDH = await computeDH(govkeypair.sec, this.govPublicKey) 
    let govAES = await HMACtoAESKey(govDH, govEncryptionDataStr)
    let cGov = await encryptWithGCM(govAES, JSON.stringify(cryptoKeyToJSON(AES_key)), ivGov)

    let salt = genRandomSalt()

    let header = {
        pub : keypair.pub,
        vGov : govkeypair.pub,
        cGov : cGov,
        ivGov : ivGov,
        salt : salt
    }

    //encrypt
    let header_string = JSON.stringify(header)
    let ciphertext = await encryptWithGCM(AES_key, plaintext, salt, header_string)

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
    /*let connState = this.conns[name]
    if(connState.keypair.pub != header.pub){
      //connState.keypair.pub = 
      //let newkeypair = await generateEG()
      let computedDH = await computeDH(keypair.sec, cert.pub)
    }
    */


    return plaintext
  }
};

module.exports = {
  MessengerClient
}
