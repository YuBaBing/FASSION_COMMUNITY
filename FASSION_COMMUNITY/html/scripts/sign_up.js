// 회원가입 함수: 백엔드 API를 호출해 새 사용자 등록
function signup() {
    // HTML에서 username과 password 입력값 가져오기
    const username = document.querySelector("input[name='username']").value; // name="username"인 input
    const password = document.querySelector("input[name='password']").value; // name="password"인 input
    const btn = document.getElementById("btn"); // 버튼 요소 (선택)

    // 입력값 유효성 검사
    if (!username || !password) {
        alert("ID와 비밀번호를 입력하세요!");
        return;
    }

    // 백엔드에 회원가입 요청 보내기
    fetch('http://localhost:3000/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }) // 사용자 정보 JSON으로 전송
    })
    .then(response => {
        if (!response.ok) { // HTTP 상태 코드가 200~299 아니면 오류
            throw new Error('회원가입 요청 실패');
        }
        return response.json(); // 응답을 JSON으로 변환
    })
    .then(data => {
        if (data.success) { // 회원가입 성공
            alert('회원가입이 완료되었습니다! 로그인해주세요.');
            // 버튼 텍스트 변경 (기존 동작 유지, 선택)
            if (btn) {
                btn.textContent = "ok";
            }
            // 입력 폼 초기화 (선택)
            document.querySelector("input[name='username']").value = '';
            document.querySelector("input[name='password']").value = '';
            window.location.href = 'logs.html'; // 로그인 페이지로 이동
        } else { // 회원가입 실패 (예: 중복 ID)
            alert(data.message || '회원가입에 실패했습니다.');
        }
    })
    .catch(error => { // 네트워크 오류 등 처리
        console.error('Signup error:', error);
        alert('회원가입 중 오류가 발생했습니다. 다시 시도해주세요.');
    });
}