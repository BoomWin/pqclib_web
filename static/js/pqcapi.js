// PQC API와 통신하기 위한 클래스
class PQCAPI {
    constructor() {
        this.baseURL = 'http://localhost:5000/api';
    }

    // Kyber 키쌍 생성
    async generateKyberKeyPair(securityLevel) {
        try {
            const response = await fetch('${this.baseURL}/kyber/keypair', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ securityLevel })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to generate keypair');
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to generate Kyber keypair:', error);
            throw error;
        }
    }

    // Kyber 캡슐화
    // async kyberEncapsulate(securityLevel, publicKey) {
        
    // }
}

// 전역 PQC API 인스턴스 생성
const pqcApi = new PQCAPI();