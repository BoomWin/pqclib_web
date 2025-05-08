#ifndef _PQC_RETURN_H_
#define _PQC_RETURN_H_

#include <stdint.h>

/* 공통 상태 모드 */
#define PQC_COMMON_SUCCESS                  0x00000000  /* 공통 성공 코드 */
#define PQC_COMMON_FAIL                     0x00000001  /* 공통 실패 코드 */
#define PQC_PARAMETER_ERROR                 0x00000002  /* 잘못된 매개변수 */
#define PQC_NULL_POINTER_ERROR              0x00000003  /* NULL 포인터 오류 */
#define PQC_UNSUPPORTED_ALGORITHM           0x00000004  /* 지원되지 않는 알고리즘 */


/* ML-KEM 관련 상태 코드 (0x0100 ~ 0x01FF)*/
/* ML-KEM 512 */
#define ML_KEM_512_KEYPAIR_SUCCESS          0x00000100   /* ML-KEM-512 키페어 생성 성공 */
#define ML_KEM_512_KEYPAIR_FAIL             0x00000101   /* ML-KEM-512 키페어 생성 실패 */
#define ML_KEM_512_ENCAP_SUCCESS            0x00000102   /* ML-KEM-512 캡슐화 성공 */
#define ML_KEM_512_ENCAP_FAIL               0x00000103   /* ML-KEM-512 캡슐화 실패 */
#define ML_KEM_512_DECAP_SUCCESS            0x00000104   /* ML-KEM-512 디캡슐화 성공 */
#define ML_KEM_512_DECAP_FAIL               0x00000105   /* ML-KEM-512 디캡슐화 실패 */

/* ML-KEM 768 */
#define ML_KEM_768_KEYPAIR_SUCCESS          0x00000110   /* ML-KEM-768 키페어 생성 성공 */
#define ML_KEM_768_KEYPAIR_FAIL             0x00000111   /* ML-KEM-768 키페어 생성 실패 */
#define ML_KEM_768_ENCAP_SUCCESS            0x00000112   /* ML-KEM-768 캡슐화 성공 */
#define ML_KEM_768_ENCAP_FAIL               0x00000113   /* ML-KEM-768 캡슐화 실패 */
#define ML_KEM_768_DECAP_SUCCESS            0x00000114   /* ML-KEM-768 디캡슐화 성공 */
#define ML_KEM_768_DECAP_FAIL               0x00000115   /* ML-KEM-768 디캡슐화 실패 */

/* ML-KEM 1024 */
#define ML_KEM_1024_KEYPAIR_SUCCESS         0x00000120   /* ML-KEM-1024 키페어 생성 성공 */
#define ML_KEM_1024_KEYPAIR_FAIL            0x00000121   /* ML-KEM-1024 키페어 생성 실패 */
#define ML_KEM_1024_ENCAP_SUCCESS           0x00000122   /* ML-KEM-1024 캡슐화 성공 */
#define ML_KEM_1024_ENCAP_FAIL              0x00000123   /* ML-KEM-1024 캡슐화 실패 */
#define ML_KEM_1024_DECAP_SUCCESS           0x00000124   /* ML-KEM-1024 디캡슐화 성공 */
#define ML_KEM_1024_DECAP_FAIL              0x00000125   /* ML-KEM-1024 디캡슐화 실패 */


/* ML-DSA 관련 상태 코드 (0x0200 ~ 0x02FF) */
/* ML-DSA 44 */
#define ML_DSA_44_KEYPAIR_SUCCESS           0x00000200   /* ML-DSA-44 키페어 생성 성공 */
#define ML_DSA_44_KEYPAIR_FAIL              0x00000201   /* ML-DSA-44 키페어 생성 실패 */
#define ML_DSA_44_SIGN_SUCCESS              0x00000202   /* ML-DSA-44 서명 생성 성공 */
#define ML_DSA_44_SIGN_FAIL                 0x00000203   /* ML-DSA-44 서명 생성 실패 */
#define ML_DSA_44_VERIFY_SUCCESS            0x00000204   /* ML-DSA-44 서명 검증 성공 */
#define ML_DSA_44_VERIFY_FAIL               0x00000205   /* ML-DSA-44 서명 검증 실패 */

/* ML-DSA 65 */
#define ML_DSA_65_KEYPAIR_SUCCESS           0x00000210   /* ML-DSA-65 키페어 생성 성공 */
#define ML_DSA_65_KEYPAIR_FAIL              0x00000211   /* ML-DSA-65 키페어 생성 실패 */
#define ML_DSA_65_SIGN_SUCCESS              0x00000212   /* ML-DSA-65 서명 생성 성공 */
#define ML_DSA_65_SIGN_FAIL                 0x00000213   /* ML-DSA-65 서명 생성 실패 */
#define ML_DSA_65_VERIFY_SUCCESS            0x00000214   /* ML-DSA-65 서명 검증 성공 */
#define ML_DSA_65_VERIFY_FAIL               0x00000215   /* ML-DSA-65 서명 검증 실패 */

/* ML-DSA 87 */
#define ML_DSA_87_KEYPAIR_SUCCESS           0x00000220   /* ML-DSA-87 키페어 생성 성공 */
#define ML_DSA_87_KEYPAIR_FAIL              0x00000221   /* ML-DSA-87 키페어 생성 실패 */
#define ML_DSA_87_SIGN_SUCCESS              0x00000222   /* ML-DSA-87 서명 생성 성공 */
#define ML_DSA_87_SIGN_FAIL                 0x00000223   /* ML-DSA-87 서명 생성 실패 */
#define ML_DSA_87_VERIFY_SUCCESS            0x00000224   /* ML-DSA-87 서명 검증 성공 */
#define ML_DSA_87_VERIFY_FAIL               0x00000225   /* ML-DSA-87 서명 검증 실패 */

#endif
