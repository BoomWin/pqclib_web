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
            
            const response = await fetch(`${this.baseURL}/kyber/keypair`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ securityLevel })
            });
            
            console.log(`Response status: ${response.status}`);
            
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
    async encapsulateKyber(publicKey, securityLevel) {
        try {
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

     // Dilithium 키쌍 생성
     async generateDilithiumKeyPair(securityLevel) {
        try {
            console.log(`Sending request to: ${this.baseURL}/dilithium/keypair`);
            console.log(`Security level: ${securityLevel}`);

            const response = await fetch(`${this.baseURL}/dilithium/keypair`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ securityLevel })
            });

            console.log(`Response status: ${response.status}`);

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to generate keypair');
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to generate Dilithium keypair:', error);
            throw error;
        }
    }

    async signDilithium(message, privateKey, securityLevel) {
        try {
            const response = await fetch(`${this.baseURL}/dilithium/sign`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message, privateKey, securityLevel })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to sign');
            }

            return await response.json();
        } catch (error) {
            console.error('Failed to sign Dilithium:', error);
            throw error;
        }
    }
}

// 전역 PQC API 인스턴스 생성
const pqcApi = new PQCAPI();