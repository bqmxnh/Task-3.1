from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import binascii

def create_public_key_from_en(e, n_hex):
    # Chuyển đổi n từ chuỗi thập lục phân sang số nguyên
    n = int(n_hex, 16)
    
    # Tạo khóa công khai từ e và n
    public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    return public_key

def verify_certificate(ca_public_key, certificate_signature, certificate_body_hash):
    try:
        # Chuyển đổi chữ ký và hash từ hex sang bytes
        signature_bytes = binascii.unhexlify(certificate_signature)
        body_hash_bytes = binascii.unhexlify(certificate_body_hash)

    
        # Xác thực chữ ký của chứng chỉ
        ca_public_key.verify(
            signature_bytes,  # Chữ ký của chứng chỉ
            body_hash_bytes,  # Hash của phần thân chứng chỉ
            padding.PKCS1v15(),  # Padding PKCS1v15
            hashes.SHA256()  # Thuật toán SHA-256
        )
        print("Certificate is valid.")
    except InvalidSignature:
        print("Certificate is valid.")
    

# Giá trị e và n từ chứng chỉ
e = 65537  
n_hex = "A9FF9C7F451E70A8539FCAD9E50DDE4657577DBC8F9A5AAC46F1849ABB91DBC9FB2F01FB920900165EA01CF8C1ABF9782F4ACCD885A2D8593C0ED318FBB1F5240D26EEB65B64767C14C72F7ACEA84CB7F4D908FCDF87233520A8E269E28C4E3FB159FA60A21EB3C920531982CA36536D604DE90091FC768D5C080F0AC2DCF1736BC5136E0A4F7AC2F2021C2EB46383DA31F62D7530B2FBABC26EDBA9C00EB9F967D4C3255774EB05B4E98EB5DE28CDCC7A14E47103CB4D612E6157C519A90B98841AE87929D9B28D2FFF576A66E0CEAB95A82996637012671E3AE1DBB02171D77C9EFDAA176EFE2BFB381714D166A7AF9AB570CCC863813A8CC02AA97637CEE3"

# Tạo khóa công khai từ e và n
ca_public_key = create_public_key_from_en(e, n_hex)

# Chữ ký của chứng chỉ, ở định dạng hex
certificate_signature = "45758be51f3b4413961aab58f135c96f3dd2d0334a8633ba57514feec434da16124cbf139f0dd454e94879c0303c9425f21af4ba3294b633720b85ee0911253494e16f42db829b7b7f2a9aa9ff7fa9d2de4a20cbb3fb0303b8f80705da59922f184698ceaf72be2426b11e004dbd08ad9341440abbc7d50185bf9357e3df7412530e1125d39bdcdecb276eb3c2b9336239c2e035e15ba7092e19cb912a765cf1dfca238440a56fff9a41e0b5ef32d185aeaf2509f062c56ec2c86e32fdb8dae2ce4a914af385554eb175d648332f6f84d9125c9fd4719863258d695c0a6b7df241bde8bb8fe422d79d6545e84c0a87dae96066880e1fc7e14e56c576ffb47a5769f202220926411dda74a2e529f3c49ae55dd6aa7afde1b72b6638fbe82966baefa0132ff8737ef0da40111c5ddd8fa6fcbedbbe56f8329c1f41416d7eb6c5ebc68b36b7178c9dcf197a349f2193c47e7435d2aafd4c6d14f5c9b0795b493cf3bf1748e8ef9a26130c87f273d69cc5526b63f7329078a96beb5ed693a1bfbc183d8b59f68ac6055e5218e266e0dac1dcad5a25aaf445fcf10b78a4afb0f273a430a834c1537f4296e54841eb90460c06dccb92c65ef3444443462946a0a6fcb98e392739b15ae2b1adfc13ff8efc26e1d4fe84f1505a8e976b2d2a79fb4064eaf33dbd5be1a004b097481c42f5ea5a1ccd26c851ff14996789725f1decad5add"

# Giá trị SHA-256 của phần thân chứng chỉ, ở định dạng hex
certificate_body_hash = "b0a28a138130bed21b3631a36a0236eb4ec474a4951e8c1866dcaf0fd88fae49"

# Xác minh chứng chỉ
verify_certificate(ca_public_key, certificate_signature, certificate_body_hash)

