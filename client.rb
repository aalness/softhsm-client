require "rubygems"
require "pkcs11"
require "bitcoin"
include PKCS11

# Using https://github.com/opendnssec/SoftHSMv2
PATH_TO_VENDOR_CRYPTOKI = '/usr/local/lib/softhsm/libsofthsm2.so'

def get_session(pin, rw=false)
  flags = CKF_SERIAL_SESSION
  flags |= CKF_RW_SESSION if rw
  pkcs11 = PKCS11.open(PATH_TO_VENDOR_CRYPTOKI)
  session = pkcs11.active_slots.first.open(flags)
  session.login(:USER, pin)
  session
end

# Generate AES256 secret
def generate_master(session)
  session.generate_key(:AES_KEY_GEN, :LABEL => 'master key', :VALUE_LEN => 256>>3, :TOKEN => true)
end

# Fetch a handle to the secret
def fetch_master(session)
  session.find_objects do |obj|
    return obj if obj[:LABEL] == 'master key'
  end
end

# Encrypt a Bitcoin key
def encrypt_bitcoin_key(session, master_key, bitcoin_key)
  iv = SecureRandom.random_bytes
  ciphertxt = session.encrypt({:AES_CBC => iv}, master_key, bitcoin_key.priv)
  [ iv, ciphertxt ]
end

# Decrypt a Bitcoin key
def decrypt_bitcoin_key(session, master_key, iv, encrypted_bitcoin_key)
  session.decrypt({:AES_CBC => iv}, master_key, encrypted_bitcoin_key)
end

session = get_session('1234', true)

# Uncomment to create the master secret
#master_key = generate_master(session)
master_key = fetch_master(session)

# Generate a key
key = Bitcoin::Key.generate
puts "Generated new private key: #{key.priv}"
# Encrypt a key
iv, encrypted_key = encrypt_bitcoin_key(session, master_key, key)
puts "Encrypted private key: #{encrypted_key.unpack('H*').first}"
# Decrypt a key
decrypted_key = decrypt_bitcoin_key(session, master_key, iv, encrypted_key)
key = Bitcoin::Key.new(decrypted_key)
puts "Re-created private key: #{key.priv}"

session.logout
