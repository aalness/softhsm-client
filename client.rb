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

def generate_wrapper(session)
  session.generate_key(:AES_KEY_GEN, :LABEL => 'master key', :VALUE_LEN => 256>>3, :TOKEN => true)
end

def fetch_wrapper(session)
  pub_key, priv_key = nil, nil
  session.find_objects do |obj|
    return obj if obj[:LABEL] == 'master key'
  end
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

# Sign the message
puts "Signing text"
signature = "\03"+session.sign(:ECDSA, priv_key, "oh hey there")
puts "Signature: #{signature.unpack("H*").first}"

# Verify the message
key.verify_message([signature].pack("m0"), "oh hey there")
puts "Signature verified"

session.logout
