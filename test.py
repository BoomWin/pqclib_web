# API 엔드포인트 : Dilithium 서명
@app.route('/api/dilithium/sign', methods=['POST'])
def dilithium_sign():
    data = request.json
    security_level = data.get('securityLevel', ALG_MLDSA44)
    message = data.get('message')
    private_key_hex = data.get('privateKey')

    if not private_key_hex:
        return jsonify({'error': 'Public Key is required'}), 400
    
    try:
        sizes = get_dilithium_sizes(security_level)

        # Hex 문자열을 바이트로 변환
        try:
            message_bytes = bytes.fromhex(message)
            message_buf = (ctypes.c_ubyte * len(message_bytes))(*message_bytes)
            private_key_bytes = bytes.fromhex(private_key_hex)
            
        except ValueError:
            return jsonify({'error': 'Invalid hex format for private key'}), 400
        
        if len(private_key_bytes) != sizes['sk_size']:
            return jsonify({'error': f'Invalid private key size. Expected {sizes["sk_size"]} bytes'}), 400

        sk = (ctypes.c_ubyte * sizes['sk_size'])()
        for i, b in enumerate(private_key_bytes):
            sk[i] = b
        # c라이브러리에서 호출하기 위해서 사이즈 할당
        sig = (ctypes.c_ubyte * sizes['sig_size'])()
        # c 라이브러리에서 siglen도 포인터 형태로 넘겨주기 때문에
        siglen = ctypes.c_size_t()

        result = pqc_lib.Sign_Signature(sig, ctypes.byref(siglen), message_buf, len(message_bytes), sk, security_level)

        if result < 0:
            return jsonify({'error': f'Signing failed with code: {result}'}), 500

        # Hex 인코딩 사용
        sig_hex = bytes(sig).hex()

        return jsonify({
            'Signature' : sig_hex
        })   
    except ValueError as e:
        return jsonify({'error': str(e)}), 400