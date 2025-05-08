#ifndef _PQC_EXTERN_H_
#define _PQC_EXTERN_H_

#include <stdint.h>
#include <stddef.h>

// KEM 관련 함수 (ML-KEM)
extern int Kem_Keypair(
    uint8_t *pk,
    uint8_t *sk,
    unsigned int algorithm);

/*
ct : 암호화된 데이터를 저장할 버퍼
ss : 암호화 과정에서 생성된 공유 비밀키를 저장할 버퍼 
(공유 비밀은 통신 세션에서 실제 데이터 암호화에 사용되는 대칭키를 도출하는데 활용된다.)
pk : 수신자의 공개키, 이 공개키를 사용하여 메시지를 암호화하고 공유 비밀키를 생성함.
*/
extern int Kem_Encapsulate(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk,
    unsigned int algorithm);

extern int Kem_Decapsulate(
    uint8_t *ss,
    const uint8_t *ct,
    const uint8_t *sk,
    unsigned int algorithm);


// 서명 관련 함수 (ML-DSA)
extern int Sign_Keypair(
    uint8_t *pk,
    uint8_t *sk,
    unsigned int algorithm);

extern int Sign_Signature(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    unsigned int algorithm);

extern int Sign_Verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk,
    unsigned int algorithm);

#endif // _PQC_EXTERN_H_