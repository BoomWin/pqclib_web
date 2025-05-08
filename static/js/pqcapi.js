// PQC API와 통신하기 위한 클래스
class PQCAPI {
    constructor() {
        this.baseURL = 'http://localhost:5000/api';
    }

    // Kyber 키쌍 생성
    async generateKyberKeyPair(securityLevel) {
        try {

            console.log(`Sending request to: ${this.baseURL}/kyber/keypair`);
            console.log(`Security level: ${securityLevel}`);
            // 작은 따옴표(')가 아닌 백틱(`)을 사용하세요
            const response = await fetch(`${this.baseURL}/kyber/keypair`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ securityLevel })
            });

            console.log('Response status: ${response.status}');
            const responseText = await response.text();
            console.log('Response text: ${responseText}');
            
            if (!response.ok) {
                throw new Error(error.error || 'Failed to generate keypair');
            }

            // 텍스트를 JSON으로 파싱
            const jsonData = JSON.parse(responseText);
            return jsonData;
        } catch (error) {
            console.error('Failed to generate Kyber keypair:', error);
            throw error;
        }
    }

    // Kyber 캡슐화
    async encapsulateKyber(publicKey, securityLevel) {
        try {
            // 백틱 사용
            const response = await fetch(`${this.baseURL}/kyber/encapsulate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ publicKey, securityLevel })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to encapsulate');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Failed to encapsulate Kyber:', error);
            throw error;
        }
    }

    // Kyber 복호화
    async decapsulateKyber(ciphertext, privateKey, securityLevel) {
        try {
            // 백틱 사용
            const response = await fetch(`${this.baseURL}/kyber/decapsulate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ciphertext, privateKey, securityLevel })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to decapsulate');
            }
            
            return await response.json();
        } catch (error) {
            console.error('Failed to decapsulate Kyber:', error);
            throw error;
        }
    }
}

// 전역 PQC API 인스턴스 생성
const pqcApi = new PQCAPI();