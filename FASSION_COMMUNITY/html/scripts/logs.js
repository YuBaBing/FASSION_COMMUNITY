// 로그인 함수: 백엔드 API를 호출해 사용자 인증
function login() {
    // HTML에서 입력값 가져오기
    const username = document.querySelector("input[name='username']").value; // name="username"인 입력란의 값
    const password = document.querySelector("input[name='password']").value; // name="password"인 입력란의 값

    // 입력값 확인: username 또는 password가 비어있으면 경고
    if (!username || !password) {
        alert("ID와 비밀번호를 입력하세요!"); // 사용자에게 메시지 표시
        return; // 함수 종료
    }

    // 백엔드에 로그인 요청 보내기 (POST /api/login)
    fetch('http://localhost:3000/api/login', {
        method: 'POST', // HTTP POST 요청
        headers: { 'Content-Type': 'application/json' }, // 요청 데이터가 JSON 형식임을 명시
        body: JSON.stringify({ username, password }), // 사용자 이름과 비밀번호를 JSON으로 변환해 전송
        credentials: 'include'
    })

    .then(response => {
        console.log('Login response:', response.status); // 디버깅
        if (!response.ok) { // 응답 상태가 200~299가 아니면 (예: 401, 500)
            throw new Error('로그인 요청 실패'); // 오류 발생
        }
        return response.json(); // 서버 응답을 JSON으로 변환
    })
    .then(data => {
        console.log('Login data:', data); // 디버깅
        if (data.success) { // 로그인 성공 시
            // 백엔드에서 받은 JWT 토큰과 사용자 이름 저장
            localStorage.setItem('loggedInUser', JSON.stringify({ username: data.username })); // 사용자 정보 저장 (예: { username: "song" })
            window.location.href = 'home.html'; // 홈 페이지로 이동
        } else { // 로그인 실패 시
            alert(data.message || 'ID 또는 비밀번호가 잘못되었습니다.'); // 서버 메시지 또는 기본 오류 표시
        }
    })
    .catch(error => { // 네트워크 오류 또는 기타 문제 처리
        console.error('Login error:', error); // 콘솔에 오류 로그 출력
        alert('로그인 중 오류가 발생했습니다. 다시 시도해주세요.'); // 사용자에게 오류 메시지
    });
}

