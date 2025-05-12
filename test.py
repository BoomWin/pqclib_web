# API 엔드포인트 : Kyber 캡슐화
@app.route('/api/kyber/encapsulate', methods=['POST'])
def kyber_encapsulate():
    data = request.json
    security_level = data.get('securityLevel', ALG_MLKEM512)
    public_key_hex = data.get('publicKey')
    
    if not public_key_hex:
        return jsonify({'error': 'Public key is required'}), 400
    
    try:
        sizes = get_kyber_size(security_level)
        
        # Hex 문자열을 바이트로 변환
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
        except ValueError:
            return jsonify({'error': 'Invalid hex format for public key'}), 400
        
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
        
        # Hex 인코딩 사용
        ct_hex = bytes(ct).hex()
        ss_hex = bytes(ss).hex()
        
        return jsonify({
            'ciphertext': ct_hex,
            'sharedSecret': ss_hex
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400