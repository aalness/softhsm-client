require "rubygems"
require "pkcs11"
require "bitcoin"
include PKCS11
include Bitcoin::Builder

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

def generate_wrapper(session)
  session.generate_key(:AES_KEY_GEN, :LABEL => 'master key', :VALUE_LEN => 256>>3, :TOKEN => true)
end

def fetch_wrapper(session)
  pub_key, priv_key = nil, nil
  session.find_objects do |obj|
    return obj if obj[:LABEL] == 'master key'
  end
end

# Create a tx that sends to self based on a fake previous output
def create_tx(addr, value)
  new_tx = Bitcoin::Protocol::Tx.new
  txout = Bitcoin::Protocol::TxOut.value_to_address(value, addr)
  new_tx = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
  txin = Bitcoin::Protocol::TxIn.new(new_tx.binary_hash, 0, txout)
  new_tx.add_in txin
  new_tx.add_out txout
  new_tx
end

# Start session
session = get_session('1234', true)

# Uncomment to create the wrapper key
#wrapper_key = generate_wrapper(session)
wrapper_key = fetch_wrapper(session)

# Generate a Bitcoin key pair
puts "Generating key pair"
group = OpenSSL::PKey::EC::Group.new('secp256k1')
pub_key, priv_key = session.generate_key_pair(:EC_KEY_PAIR_GEN,
                                              {:VERIFY=>true, :EC_PARAMS=>group.to_der},
                                              {:ID=>'bitcoin', :SIGN=>true, :EXTRACTABLE=>true})
ec_point = pub_key[:EC_POINT].unpack("H1H1H*").last # hexify, trim leading 2 bytes which I guess are type and size?
key = Bitcoin::Key.new(nil, ec_point); key.instance_eval{ @pubkey_compressed = true };
puts "Address: #{key.addr}"

# Export wrapped private key
puts "Wrapping private key"
wrapped_key_value = session.wrap_key(:AES_KEY_WRAP, wrapper_key, priv_key)
puts "Encrypted private key: #{wrapped_key_value.unpack("H*").first}"

# Unwrap private key and return a handle to it
puts "Unwrapping private key"
priv_key = session.unwrap_key(:AES_KEY_WRAP, wrapper_key, wrapped_key_value, :CLASS=>CKO_PRIVATE_KEY, :KEY_TYPE=>CKK_EC, :SIGN=>true)

# Create tx
tx = create_tx(key.addr, 50000)
sighash = tx.signature_hash_for_input(0, tx.out[0].script)

# Sign the tx
puts "Signing tx"
signature = session.sign(:ECDSA, priv_key, sighash)
# Poor-man's DER encoded signature, see: http://crypto.stackexchange.com/a/1797
signature = "\x30\x44\x02\x20" + signature.slice(0, 32) + "\x02\x20" + signature.slice(32, 32)
tx.in[0].script_sig = Bitcoin::Script.to_signature_pubkey_script(signature, [key.pub].pack("H*"))

# Verify the signature
if tx.verify_input_signature(0, tx.out[0].script)
  puts "Signature verified"
else
  raise "Nope :("
end

session.logout
