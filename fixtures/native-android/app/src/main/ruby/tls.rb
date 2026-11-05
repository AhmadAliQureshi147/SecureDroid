require "openssl"

def client
  OpenSSL::SSL::VERIFY_NONE
end
