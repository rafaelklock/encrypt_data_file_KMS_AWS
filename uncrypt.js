const fs = require('fs');
var AWS = require('aws-sdk');
var fernet = require('fernet');


var credentials = new AWS.SharedIniFileCredentials({profile: 'AWS-PROFILE-DEV'});
AWS.config.region = 'sa-east-1'
AWS.config.credentials = credentials;
var kms = new AWS.KMS();


const fileName = 'meuarquivocriptografado.json'
const NUM_BYTES_FOR_LEN = 4;


try {
    var data = fs.readFileSync(fileName) 
} catch (err) {
    console.error(err)
}


data_key_encrypted_len = data.slice(0, NUM_BYTES_FOR_LEN).readUIntBE(0, NUM_BYTES_FOR_LEN) + NUM_BYTES_FOR_LEN;
data_key_encrypted = data.slice(NUM_BYTES_FOR_LEN, data_key_encrypted_len)
data_contents = data.slice(data_key_encrypted_len)


var params = {CiphertextBlob: data_key_encrypted};
kms.decrypt(params, function(err, data) {
    if (err) {
        console.log(err, err.stack);
    } else {
        var data_key_plaintext = data.Plaintext.toString('base64');
        var content_encrypted = data_contents.toString();
        var secret = new fernet.Secret(data_key_plaintext)

        var token = new fernet.Token({
            secret: secret,
            token: content_encrypted,
            ttl: 0
          })
        var resultado = token.decode();
        //console.log(resultado);
    }
});
