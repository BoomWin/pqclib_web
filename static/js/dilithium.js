// Dilithium 관련 UI 로직
// dilithium 보안 레벨 가져오기 (모든 연산을 위해 필요함)
function getSecurityLevel() {
    return parseInt(document.getElementById('global-security-level').value);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

    document.addEventListener('DOMContentLoaded', () => {
    const messageInput = document.getElementById('ml-dsa-sign-msg');
    const fileInput = document.getElementById('file-sign');
    const fileNameDisplay = document.getElementById('file-name-sign');

  // 메시지 입력 시 파일 선택 비활성화
  messageInput.addEventListener('input', () => {
    if (messageInput.value.trim()) {
      fileInput.disabled = true;
      // 파일 선택이 되어 있다면 초기화
      fileInput.value = '';
      fileNameDisplay.textContent = '';
    } 
    else {
      fileInput.disabled = false;
    }
  });

  // 파일 선택 시 메시지 입력 비활성화
  fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];

    if (file) {
      messageInput.disabled = true;
      messageInput.value = '';
      fileNameDisplay.textContent = file.name;
    }
    else {
      messageInput.disabled = false;
      fileNameDisplay.textContent = '';
    }
  });

  // 검증 부분에도 동일한 로직 적용
  const verifyMessageInput = document.getElementById('ml-dsa-verify-msg');
  const verifyFileInput = document.getElementById('file-verify');
  const verifyFileNameDisplay = document.getElementById('file-name-verify');
  
  // 메시지 입력 시 파일 선택 비활성화
  verifyMessageInput.addEventListener('input', () => {
    if (verifyMessageInput.value.trim()) {
      verifyFileInput.disabled = true;
      // 파일 선택이 되어 있었다면 초기화
      verifyFileInput.value = '';
      verifyFileNameDisplay.textContent = '';
    } else {
      verifyFileInput.disabled = false;
    }
  });
  
  // 파일 선택 시 메시지 입력 비활성화
  verifyFileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    
    if (file) {
      verifyMessageInput.disabled = true;
      verifyMessageInput.value = '';
      verifyFileNameDisplay.textContent = file.name;
    } else {
      verifyMessageInput.disabled = false;
      verifyFileNameDisplay.textContent = '';
    }
  });

  
  // 초기화 버튼 기능 구현
  const resetSignButton = document.getElementById('reset-sign-btn');
  if (resetSignButton) {
    resetSignButton.addEventListener('click', () => {
      messageInput.value = '';
      messageInput.disabled = false;
      fileInput.value = '';
      fileInput.disabled = false;
      fileNameDisplay.textContent = '';
      document.getElementById('ml-dsa-sign-sk').value = '';
      document.getElementById('ml-dsa-signature').value = '';
    });
  }

  const resetVerifyButton = document.getElementById('reset-verify-btn');
  if (resetVerifyButton) {
    resetVerifyButton.addEventListener('click', () => {
      verifyMessageInput.value = '';
      verifyMessageInput.disabled = false;
      verifyFileInput.value = '';
      verifyFileInput.disabled = false;
      verifyFileNameDisplay.textContent = '';
      document.getElementById('ml-dsa-verify-pk').value = '';
      document.getElementById('ml-dsa-verify-sig').value = '';
      document.getElementById('verify-result').textContent = '-';
      document.getElementById('verify-result').style.color = '';
    });
  }
});

// dilithium keypair 생성 기능 처리 버튼 정의
document.getElementById('ml-dsa-generate-keypair-btn').addEventListener('click', async () => {
  try {
    const result = await pqcApi.generateDilithiumKeyPair(getSecurityLevel());
    document.getElementById('ml-dsa-public-key').value = result.publicKey;
    document.getElementById('ml-dsa-private-key').value = result.privateKey;
  }
  catch (error) {
    alert('키쌍 생성에 실패했습니다: ' + error.message);
  }
});

// dilithium 키 쌍 초기화 기능 처리 버튼 정의
document.getElementById('ml-dsa-reset-keypair-btn').addEventListener('click', () => {
  document.getElementById('ml-dsa-public-key').value = '';
  document.getElementById('ml-dsa-private-key').value = '';
});



// dilithium 서명 기능 처리 버튼 정의
// 서명하기 버튼에 이벤트 리스너 추가해서 웹 <-> js <-> flask 통신 유도
document.getElementById('ml-dsa-sign-btn').addEventListener('click', async () => {
  const privateKey = document.getElementById('ml-dsa-sign-sk').value;
  const messageInput = document.getElementById('ml-dsa-sign-msg');
  const fileInput = document.getElementById('file-sign');

  if (!privateKey) {
    alert('비밀키를 입력해주세요.');
    return;
  }

  try {
    // 텍스트 메시지를 바이트 배열로 저장할 변수
    let message;
    // 1차 if로 이후에는 else if로 구성할 예정
    // 메시지 입력과 파일 선택 중 어떤 것이 활성화되어 있는지 확인
    if (!messageInput.disabled && messageInput.value.trim()) {
      // 사용자가 메시지를 직접 입력한 경우
      // 자바스크립트 문자열을 uint8array 형식의 바이트 배열로 변환한 것임.
      const encoder = new TextEncoder();
      message = encoder.encode(messageInput.value);
      message = bytesToHex(message); // hex String으로 변환 백엔드레벨에서 hex를 기대함.
    }
    // 파일 선택 입력이 활성화 되어 있고 값이 있는 경우
    else if (!fileInput.disabled && fileInput.files.length > 0) {
      const file = fileInput.files[0];
      const fileReader = new FileReader();

      // 파일 읽기 Promise 생성
      // 근데 파일 읽기 할 때 일정 용량 넘어가면 거부 떄리는 것 넣어줘야 할듯 서버터질 것 같음.
      const fileLoadPromise = new Promise((resolve, reject) => {
        fileReader.onload = (e) => resolve(e.target.result);
        fileReader.onerror = (e) => reject(new Error('파일 읽기 실패'));

      });

      // 파일을 ArrayBuffer로 읽기
      fileReader.readAsArrayBuffer(file);

      // 파일 읽기 완료 대기
      const fileData = await fileLoadPromise;
      // 파일 읽은거 Uint8 형식의 배열로 message에 넣어줌.
      message = new Uint8Array(fileData);
      message = bytesToHex(message); // hex String으로 변환 백엔드레벨에서 hex를 기대함.
    }
    // 메시지도, 파일도 없는 경우
    else {
      alert('메시지 입력 또는 파일을 선택해주세요.');
      return;
    }
    
    // 보안 레벨 가져오기
    const securityLevel = getSecurityLevel();

    // 서명 생성 API 호출
    const result = await pqcApi.signDilithium(message, privateKey, securityLevel);

    // 서명 결과 표시
    document.getElementById('ml-dsa-signature').value = result.Signature;

  }
  catch (error) {
    alert('서명 생성 실패했습니다: ' + error.message);
  }
});

