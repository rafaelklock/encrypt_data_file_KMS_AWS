var AWS = require('aws-sdk');
var fernet = require('fernet');


class Crypt {


    static createInstance() {
        return new Crypt()
    }


    constructor(){
        this.NUM_BYTES_FOR_LEN = 4 
        this.get_credenctials()
    }


    get_credenctials(){
            var credentials = new AWS.SharedIniFileCredentials({profile: 'DEV'});
            AWS.config.update({
                credentials: credentials,
                region: 'sa-east-1'
            })
        this.kms = new AWS.KMS();
    }


    async PegaCMK() {

        var params = {};
        
        var response = await this.kms.listKeys(params).promise();
        response.Keys.forEach(function(elemento, i) {
        
            var params = {
                KeyId: elemento['KeyId']
            };
            console.log(params);
            
        });
        

    }

    async DecodeDataKey(data_key_encrypted) {
        const params = {CiphertextBlob: data_key_encrypted};
        var data = await this.kms.decrypt(params).promise();
        var data_key_plaintext = data.Plaintext.toString('base64');
        return data_key_plaintext;
    }


    async Decode(file){
        
        var data_key_encrypted_len = file.slice(0, this.NUM_BYTES_FOR_LEN).readUIntBE(0, this.NUM_BYTES_FOR_LEN) + this.NUM_BYTES_FOR_LEN;
        var data_key_encrypted = file.slice(this.NUM_BYTES_FOR_LEN, data_key_encrypted_len)
        var data_contents = file.slice(data_key_encrypted_len)
        
        const params = {CiphertextBlob: data_key_encrypted};
        
        var data = await this.kms.decrypt(params).promise();
        var data_key_plaintext = data.Plaintext.toString('base64');
        var content_encrypted = data_contents.toString();
        var secret = new fernet.Secret(data_key_plaintext)
    
        var token = new fernet.Token({
            secret: secret,
            token: content_encrypted,
            ttl: 0
        })
        return token.decode()
    }


    async geraChave(cmk_id){
        var params = {
            KeyId: cmk_id, 
            KeySpec: "AES_256"
           };

        var data = await this.kms.generateDataKey(params).promise();
        var dataKey = data.CiphertextBlob;
        var dataKeyPlainText = data.Plaintext;
        return [dataKey, dataKeyPlainText]

    }


    async Encode(contentData) {
        var dataKey = await this.geraChave('0c7ea163-8597-4ed6-8971-3220f5db142f')

        var dataKeyEncrypted = dataKey[0];
        var dataKeyPlainText = dataKey[1].toString('base64');
        
        
        var chave = new fernet.Secret(dataKeyPlainText);
        var token = new fernet.Token({
            secret: chave,
            time: Date.parse(1),
            iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        })
        var contentsEncrypted = await token.encode(contentData);


        var len = dataKeyEncrypted.length;

        var buffer_len = Buffer(4);
        buffer_len.writeUIntBE(len, 0, 4);
        

        var DataEncrypted = Buffer.concat([buffer_len, Buffer.from(dataKeyEncrypted), Buffer.from(contentsEncrypted)]);
        
        return DataEncrypted;

    }


    
}

module.exports = Crypt;
