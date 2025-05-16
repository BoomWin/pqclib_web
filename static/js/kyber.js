// Kyber 관련 UI 로직
// 보안 레벨 가져오기
    function getSecurityLevel() {
        return parseInt(document.getElementById('global-security-level').value);
    }

    // 키쌍 생성
    document.getElementById('generate-keypair').addEventListener('click', async () => {
    try {
        const result = await pqcApi.generateKyberKeyPair(getSecurityLevel());
        document.getElementById('public-key').value = result.publicKey;
        document.getElementById('private-key').value = result.privateKey;
    } catch (error) {
        alert('키쌍 생성에 실패했습니다: ' + error.message);
    }
    });

    // 키쌍 초기화
    document.getElementById('reset-keypair').addEventListener('click', () => {
    document.getElementById('public-key').value = '';
    document.getElementById('private-key').value = '';
    });

    // 캡슐화
    document.getElementById('encapsulate').addEventListener('click', async () => {
    const publicKey = document.getElementById('encapsulate-pk').value;
    if (!publicKey) {
        alert('공개키를 입력해주세요.');
        return;
    }

    try {
        const result = await pqcApi.encapsulateKyber(publicKey, getSecurityLevel());
        document.getElementById('ciphertext').value = result.ciphertext;
        document.getElementById('shared-secret1').value = result.sharedSecret;
    } catch (error) {
        alert('캡슐화에 실패했습니다: ' + error.message);
    }
    });

    // 캡슐화 초기화
    document.getElementById('reset-encapsulate').addEventListener('click', () => {
    document.getElementById('encapsulate-pk').value = '';
    document.getElementById('ciphertext').value = '';
    document.getElementById('shared-secret1').value = '';
    });

    // 디캡슐화
    document.getElementById('decapsulate').addEventListener('click', async () => {
    const ciphertext = document.getElementById('decapsulate-ct').value;

    const privateKey = document.getElementById('decapsulate-sk').value;
    if (!ciphertext || !privateKey) {
        alert('암호문과 비밀키를 입력해주세요.');
        return;
    }

    try {
        const result = await pqcApi.decapsulateKyber(ciphertext, privateKey, getSecurityLevel());
        document.getElementById('shared-secret2').value = result.sharedSecret;
        
    } catch (error) {
        alert('디캡슐화에 실패했습니다: ' + error.message);
    }
    });

    // 디캡슐화 초기화
    document.getElementById('reset-decapsulate').addEventListener('click', () => {
    document.getElementById('decapsulate-ct').value = '';
    document.getElementById('decapsulate-sk').value = '';
    document.getElementById('shared-secret2').value = '';
    });


    // 복사 버튼 기능
    document.querySelectorAll('.kyber-copy-btn').forEach(button => {
    button.addEventListener('click', () => {
    const targetId = button.getAttribute('data-target');
    const text = document.getElementById(targetId).value;
    if (text) {
        navigator.clipboard.writeText(text).then(() => {
        alert('복사되었습니다.');
        }).catch(err => {
        console.error('복사 실패:', err);
        });
    } else {
        alert('복사할 내용이 없습니다.');
    }
    });
});

