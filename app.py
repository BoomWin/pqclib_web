# Flask 서버 메인 애플리케이션 파일
from flask import Flask, render_template, request, jsonify
import ctypes
import os
import base64

app = Flask(__name__)

# C 라이브러리 로드
current_dir = os.path.dirname(os.path.abspath(__file__))
lib_path = os.path.join(current_dir, 'lib', 'libpqcapi_1.0-x64_linux_type1.so')
pqc_lib = ctypes.CDLL(lib_path)

# 알고리즘 상수 정의
ALG_MLKEM512 = 1
ALG_MLKEM768 = 2
ALG_MLKEM1024 = 3
ALG_MLDSA44 = 4
ALG_MLDSA65 = 5
ALG_MLDSA87 = 6

# KEM 키 길이 정의
MLKEM512_PUBLIC_KEY_BYTES = 800
MLKEM512_CIPHERTEXT_BYTES = 768
MLKEM512_SECRET_KEY_BYTES = 1632
MLKEM512_SHARED_SECRET_BYTES = 32

MLKEM768_PUBLIC_KEY_BYTES = 1184
MLKEM768_CIPHERTEXT_BYTES = 1088
MLKEM768_SECRET_KEY_BYTES = 2400
MLKEM768_SHARED_SECRET_BYTES = 32

MLKEM1024_PUBLIC_KEY_BYTES = 1568
MLKEM1024_CIPHERTEXT_BYTES = 1568
MLKEM1024_SECRET_KEY_BYTES = 3168
MLKEM1024_SHARED_SECRET_BYTES = 32

# DSA 키 길이 정의
MLDSA44_PUBLIC_KEY_BYTES = 1312
MLDSA44_SECRET_KEY_BYTES = 2560
MLDSA44_SIGNATURE_BYTES = 2420

MLDSA65_PUBLIC_KEY_BYTES = 1952
MLDSA65_SECRET_KEY_BYTES = 4032
MLDSA65_SIGNATURE_BYTES = 3309

MLDSA87_PUBLIC_KEY_BYTES = 2592
MLDSA87_SECRET_KEY_BYTES = 4896
MLDSA87_SIGNATURE_BYTES = 4627

# C 함수 시그니처 설정
pqc_lib.Kem_Keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
pqc_lib.Kem_Keypair.restype = ctypes.c_int

pqc_lib.Kem_Encapsulate.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), 
                                    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
pqc_lib.Kem_Encapsulate.restype = ctypes.c_int

pqc_lib.Kem_Decapsulate.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), 
                                   ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
pqc_lib.Kem_Decapsulate.restype = ctypes.c_int

pqc_lib.Sign_Keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
pqc_lib.Sign_Keypair.restype = ctypes.c_int

pqc_lib.Sign_Signature.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t),
                                  ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
pqc_lib.Sign_Signature.restype = ctypes.c_int

pqc_lib.Sign_Verify.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
pqc_lib.Sign_Verify.restype = ctypes.c_int

# 알고리즘에 따른 키 크기 반환 함수
def get_kyber_size(security_level):
    if security_level == ALG_MLKEM512:
        return {
            'pk_size': MLKEM512_PUBLIC_KEY_BYTES,
            'sk_size': MLKEM512_SECRET_KEY_BYTES,
            'ct_size': MLKEM512_CIPHERTEXT_BYTES,
            'ss_size': MLKEM512_SHARED_SECRET_BYTES
        }
    elif security_level == ALG_MLKEM768:
        return {
            'pk_size': MLKEM768_PUBLIC_KEY_BYTES,
            'sk_size': MLKEM768_SECRET_KEY_BYTES,
            'ct_size': MLKEM768_CIPHERTEXT_BYTES,
            'ss_size': MLKEM768_SHARED_SECRET_BYTES
        }
    elif security_level == ALG_MLKEM1024:
        return {
            'pk_size': MLKEM1024_PUBLIC_KEY_BYTES,
            'sk_size': MLKEM1024_SECRET_KEY_BYTES,
            'ct_size': MLKEM1024_CIPHERTEXT_BYTES,
            'ss_size': MLKEM1024_SHARED_SECRET_BYTES
        }
    else:
        raise ValueError(f"Unsupported Kyber security level: {security_level}")
    
# 보안 레벨에 맞게 사이즈 할당.
def get_dilithium_sizes(security_level):
   if security_level == ALG_MLDSA44:
        return {
            'pk_size': MLDSA44_PUBLIC_KEY_BYTES,
            'sk_size': MLDSA44_SECRET_KEY_BYTES,
            'sig_size': MLDSA44_SIGNATURE_BYTES
        }
    elif security_level == ALG_MLDSA65:
        return {
            'pk_size': MLDSA65_PUBLIC_KEY_BYTES,
            'sk_size': MLDSA65_SECRET_KEY_BYTES,
            'sig_size': MLDSA65_SIGNATURE_BYTES
        }
    elif security_level == ALG_MLDSA87:
        return {
            'pk_size': MLDSA87_PUBLIC_KEY_BYTES,
            'sk_size': MLDSA87_SECRET_KEY_BYTES,
            'sig_size': MLDSA87_SIGNATURE_BYTES
        }
    else:
        raise ValueError(f"Unsupported Dilithium security level: {security_level}")  

# HTML 템플릿 라우트
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/kyber')
def kyber_page():
    return render_template('kyber.html')

@app.route('/dilithium')
def dilithium_page():
    return render_template('dilithium.html')

# API 엔드포인트 : Kyber 키쌍 생성
@app.route('/api/kyber/keypair', methods=['POST'])
def kyber_keypair():
    data = request.json
    # 이 부분은 서큐리티 레벨에 맞게 바껴야할듯 정적말고 동적으로 자바스크립트랑 통신해야할듯.
    # 이미 서큐리티레벨에 따라서 구현되게끔 바뀐 것 같기도 data.get이 securityLevel에 따라서 주는 것 같음.,
    security_level = data.get('securityLevel', ALG_MLKEM512)

    try:
        sizes = get_kyber_sizes(security_level)
        # pk 보안 레벨에 맞게 사이즈 할당됨.
        pk = (ctypes.c_ubyte * sizes['pk_size'])()
        # sk 보안 레벨에 맞게 사이즈 할당됨.
        sk = (ctypes.c_ubyte * sizes['sk_size'])()

        # 실제 함수 호출 부분.
        result = pqc_lib.Kem_Keypair(pk, sk, security_level)

        # 함수 호출 결과 체크. 0보다 작으면 에러임.
        if result < 0:
            return jsonify({'error': f'Keypair generation failed with code: {result}'}), 500
        # 정상적으로 키쌍 생성되면 키쌍 반환.
        return jsonify({
            'publicKey': base64.b64encode(bytes(pk)).decode('utf-8'),
            'privateKey': base64.b64encode(bytes(sk)).decode('utf-8')
        })
    except ValueError as e:
            return jsonify({'error': str(e)}), 400

# API 엔드포인트 : Kyber 캡슐화
@app.route('/api/kyber/encapsulate', methods=['POST'])
def kyber_encapsulate():
    data = request.json
    security_level = data.get('securityLevel', ALG_MLKEM512)
    public_key_base64 = data.get('publickey')

    if not public_key_base64:
        return jsonify({'error': 'Public key is required'}), 400
    
    try:
        sizes = get_kyber_sizes(security_level)
        public_key_bytes = base64.b64decode(public_key_base64)

        if len(public_key_bytes) != sizes['pk_size']:
            return jsonify({'error': f'Invalid public key size. Expected {sizes["pk_size"]} bytes'}), 400

        pk = (ctypes.c_ubyte * sizes['pk_size'])()
        for i, b in enumerate(public_key_bytes):
            pk[i] = b

        ct = (ctypes.c_ubyte * sizes['ct_size'])()
        ss = (ctypes.c_ubyte * sizes['ss_size'])()

        result = pqc_lib.Kem_Encapsulate(ct, ss, pk, security_level)

        if result < 0:
            return jsonify({'error': f'Encapsulation failed with code: {result}'}), 500
            
        return jsonify({
            'ciphertext': base64.b64encode(bytes(ct)).decode('utf-8'),
            'sharedSecret': base64.b64encode(bytes(ss)).decode('utf-8')
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# API 엔드포인트 : Kyber 복호화
@app.route('/api/kyber/decapsulate', methods=['POST'])
def kyber_decapsulate():
    data = request.json
    security_level = data.get('securityLevel', ALG_MLKEM512)
    ciphertext_base64 = data.get('ciphertext')
    private_key_base64 = data.get('privateKey')

    if not ciphertext_base64 or not private_key_base64:
        return jsonify({'error': 'Ciphertext and private key are required'}), 400
    
    try:
        sizes = get_kyber_sizes(security_level)
        ciphertext_bytes = base64.b64decode(ciphertext_base64)
        private_key_bytes = base64.b64decode(private_key_base64)

        if len(ciphertext_bytes) != sizes['ct_size']:
            return jsonify({'error': f'Invalid ciphertext size. Expected {sizes["ct_size"]} bytes'}), 400
        if len(private_key_bytes) != sizes['sk_size']:
            return jsonify({'error': f'Invalid private key size. Expected {sizes["sk_size"]} bytes'}), 400
        
        ct = (ctypes.c_ubyte * sizes['ct_size'])()
        for i, b in enumerate(ciphertext_bytes):
            ct[i] = b
        
        sk = (ctypes.c_ubyte * sizes['sk_size'])()
        for i, b in enumerate(private_key_bytes):
            sk[i] = b
        
        ss = (ctypes.c_ubyte * sizes['ss_size'])()

        result = pqc_lib.Kem_Decapsulate(ss, ct, sk, security_level)

        if result < 0:
            return jsonify({'error': f'Decapsulation failed with code: {result}'}), 500
        
        return jsonify({
            'sharedSecret': base64.b64encode(bytes(ss)).decode('utf-8')
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


            