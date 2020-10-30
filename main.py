from crypto import retrieve_cmk, encrypt_data, decrypt_data

cmk_description = os.environ.get('AWS_CMK_DESCRIPTION', 'DataTeam Master Key')
cmk_id, cmk_arn = retrieve_cmk(cmk_description)

data = 'sensitive info'

# encrypt
encrypted_data = encrypt_data(data.encode(), cmk_id)

# decrypt:
decrypt = decrypt_data(encrypted_data)
