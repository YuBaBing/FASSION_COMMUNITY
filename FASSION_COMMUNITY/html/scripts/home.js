// 로그인 사용자 정보를 가져오는 함수
function getLoggedInUser() {
    const loggedInUser = JSON.parse(localStorage.getItem('loggedInUser')); // localStorage에서 사용자 정보 가져오기 (예: { username: "song" })
    if (!loggedInUser || !loggedInUser.username) { // 사용자 정보 또는 username이 없으면
        console.error("로그인한 사용자가 없습니다."); // 오류 메시지 출력
        return null; // null 반환 (로그인 안 된 상태)
    }
    return loggedInUser; // 사용자 객체 반환 (예: { username: "song" })
}

// 로그인 상태를 확인하는 함수
function checkLoginStatus() {
    const loggedInUser = localStorage.getItem('loggedInUser'); // localStorage에 사용자 정보 있는지 확인
    if (!loggedInUser) { // 없으면
        window.location.href = 'logs.html'; // 로그인 페이지로 이동
    }
}

// 헤더와 프로필 섹션에 사용자 이름을 표시하는 함수
function displayUsername() {
    const loggedInUser = getLoggedInUser(); // 로그인 사용자 정보 가져오기
    if (!loggedInUser) return; // 사용자 없으면 함수 종료

    const usernameDisplay = document.getElementById('username-display'); // 헤더의 사용자 이름 표시 요소
    if (usernameDisplay) {
        usernameDisplay.textContent = ` ${loggedInUser.username}님!`; // 예: " song님!"
    }

    const profileUsername = document.getElementById('profile-username'); // 프로필 섹션의 사용자 이름 요소
    if (profileUsername) {
        profileUsername.textContent = loggedInUser.username; // 예: "song"
    }
}

// 게시물에 좋아요를 추가/취소하는 함수
function likePost(button, postId) {
    const loggedInUser = getLoggedInUser(); // 로그인 사용자 확인
    if (!loggedInUser) return; // 사용자 없으면 종료

    fetch(`http://localhost:3000/api/posts/${postId}/like`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json' // 요청 데이터가 JSON임을 명시
        },
        credentials: 'include' // 쿠키를 자동으로 서버에 전송 (토큰 포함)
    })
    .then(response => response.json()) // 서버 응답을 JSON으로 변환
    .then(data => {
        if (data.success) { // 요청 성공 시
            const post = data.post; // 업데이트된 게시물 정보
            const hasLiked = post.likedBy.includes(loggedInUser.username); // 사용자가 좋아요 눌렀는지 확인
            button.querySelector('span').textContent = post.likes; // 좋아요 수 업데이트
            button.setAttribute('data-clicked', hasLiked ? 'true' : 'false'); // 버튼 상태 업데이트
            button.style.backgroundColor = hasLiked ? '#ffcccc' : ''; // 좋아요 눌렀으면 배경색 변경
        } else { // 실패 시
            alert('좋아요 처리에 실패했습니다: ' + (data.message || '알 수 없는 오류')); // 오류 메시지
        }
    })
    .catch(error => { // 네트워크 오류 처리
        console.error('Error:', error); // 오류 로그
        alert('좋아요 처리 중 오류가 발생했습니다.');
    });
}

// 게시물을 삭제하는 함수
function deletePost(postId) {
    const loggedInUser = getLoggedInUser(); // 로그인 사용자 확인
    if (!loggedInUser) {
        alert("로그인한 사용자가 없습니다. 로그인을 해주세요."); // 사용자 없으면 경고
        return;
    }

    if (!confirm("정말로 이 게시물을 삭제하시겠습니까?")) { // 삭제 확인
        return; // 취소 시 종료
    }

    fetch(`http://localhost:3000/api/posts/${postId}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json' // 요청 데이터가 JSON임을 명시
        },
        credentials: 'include' // 쿠키를 서버에 전송
    })
    .then(response => response.json()) // 응답을 JSON으로 변환
    .then(data => {
        if (data.success) { // 성공 시
            alert('게시물이 삭제되었습니다!'); // 성공 메시지
            displayMyPosts(); // 내 게시물 목록 갱신
        } else { // 실패 시
            alert('삭제에 실패했습니다: ' + (data.message || '알 수 없는 오류')); // 오류 메시지
        }
    })
    .catch(error => { // 네트워크 오류 처리
        console.error('Error:', error); // 오류 로그
        alert('삭제 중 오류가 발생했습니다.');
    });
}

// 로그아웃 처리 함수
function logout() {
    fetch('http://localhost:3000/api/logout', {
        method: 'POST',
        credentials: 'include' // 서버에 로그아웃 요청 (쿠키 삭제)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            localStorage.removeItem('loggedInUser'); // 클라이언트에서 사용자 정보 삭제
            window.location.href = 'logs.html'; // 로그인 페이지로 이동
        } else {
            alert('로그아웃에 실패했습니다: ' + (data.message || '알 수 없는 오류'));
        }
    })
    .catch(error => {
        console.error('Logout error:', error);
        localStorage.removeItem('loggedInUser'); // 안전하게 정보 삭제
        window.location.href = 'logs.html'; // 오류 발생해도 로그아웃 처리
    });
}

// 새 게시물을 추가하는 함수
function addPost() {
    const title = document.getElementById('post-title').value; // 게시물 제목 입력값
    const content = document.getElementById('post-content').value; // 게시물 내용 입력값
    const image = document.getElementById('post-image').files[0]; // 업로드된 이미지 파일

    if (!title || !content) { // 제목 또는 내용이 없으면
        alert('제목과 내용을 입력해주세요.');
        return;
    }

    const loggedInUser = getLoggedInUser(); // 로그인 사용자 확인
    if (!loggedInUser) return; // 사용자 없으면 종료

    const formData = new FormData(); // 백엔드에 보낼 데이터 준비
    formData.append('title', title); // 제목 추가
    formData.append('content', content); // 내용 추가
    if (image) formData.append('image', image); // 이미지 있으면 추가

    fetch('http://localhost:3000/api/posts', {
        method: 'POST',
        body: formData, // FormData로 데이터 전송
        credentials: 'include' // 쿠키를 서버에 전송
    })
    .then(response => response.json()) // 응답을 JSON으로 변환
    .then(data => {
        if (data.success) { // 성공 시
            alert('게시물이 업로드 되었습니다!'); // 성공 메시지
            window.location.href = 'home.html'; // 홈 페이지로 이동
        } else { // 실패 시
            alert('게시물 업로드에 실패했습니다: ' + (data.message || '알 수 없는 오류')); // 오류 메시지
        }
    })
    .catch(error => { // 네트워크 오류 처리
        console.error('Error:', error); // 오류 로그
        alert('게시물 업로드 중 오류가 발생했습니다.');
    });
}

// 모든 게시물을 표시하는 함수
function displayAllPosts() {
    const loggedInUser = getLoggedInUser(); // 로그인 사용자 확인
    if (!loggedInUser) return; // 사용자 없으면 종료

    const postContainer = document.getElementById('post-container'); // 게시물 표시 컨테이너
    if (!postContainer) {
        console.error("'post-container'를 찾을 수 없습니다."); // 컨테이너 없으면 오류
        return;
    }

    postContainer.innerHTML = ''; // 기존 게시물 지우기
    let currentPage = 1; // 현재 페이지 번호
    const postsPerPage = 4; // 한 페이지에 표시할 게시물 수

    function loadPosts(page) {
        fetch(`http://localhost:3000/api/posts?page=${page}&limit=${postsPerPage}`)
        .then(response => {
            if (!response.ok) { // 응답 오류 시
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json(); // 응답을 JSON으로 변환
        })
        .then(data => {
            const posts = data.posts || []; // 게시물 목록
            posts.forEach(post => {
                const likedBy = post.likedBy || []; // 좋아요 누른 사용자
                const hasLiked = likedBy.includes(loggedInUser.username); // 사용자가 좋아요 눌렀는지
                const postElement = document.createElement('div'); // 새 div 생성
                postElement.className = 'post'; // CSS 클래스 추가
                postElement.innerHTML = `
                    ${post.image ? `<img src="http://localhost:3000${post.image}" alt="코디 사진">` : ''} <!-- 이미지 표시 -->
                    <h3>${post.userId}</h3> <!-- 작성자 이름 -->
                    <h3>${post.title}</h3> <!-- 게시물 제목 -->
                    <p>${post.content}</p> <!-- 게시물 내용 -->
                    <button class="like-btn" onclick="likePost(this, '${post._id}')" 
                        data-clicked="${hasLiked}"
                        style="background-color: ${hasLiked ? '#ffcccc' : ''}">
                        좋아요 <span>${post.likes || 0}</span> <!-- 좋아요 버튼 -->
                    </button>
                `;
                postContainer.appendChild(postElement); // 컨테이너에 추가
            });

            const moreBtn = document.querySelector('.more-btn'); // '더 보기' 버튼
            if (moreBtn) {
                if (!data.hasMore) { // 더 이상 게시물 없으면
                    moreBtn.disabled = true;
                    moreBtn.textContent = '더 이상 게시물이 없습니다';
                } else {
                    moreBtn.disabled = false;
                    moreBtn.textContent = '더 보기';
                }
            }
        })
        .catch(error => { // 오류 처리
            console.error('Error fetching posts:', error);
            alert('게시물을 불러오는 중 오류가 발생했습니다.');
        });
    }

    loadPosts(currentPage); // 첫 페이지 로드

    const moreBtn = document.querySelector('.more-btn'); // '더 보기' 버튼 이벤트
    if (moreBtn) {
        moreBtn.addEventListener('click', () => {
            currentPage++;
            loadPosts(currentPage);
        });
    }
}

// 내 게시물을 표시하는 함수
function displayMyPosts() {
    const loggedInUser = getLoggedInUser(); // 로그인 사용자 확인
    if (!loggedInUser) return; // 사용자 없으면 종료

    const myPostContainer = document.getElementById('my-post-container'); // 내 게시물 컨테이너
    if (!myPostContainer) {
        console.error("'my-post-container'를 찾을 수 없습니다.");
        return;
    }

    myPostContainer.innerHTML = ''; // 기존 게시물 지우기

    console.log('Fetching posts for user:', loggedInUser.username); // 디버깅 로그
    fetch(`http://localhost:3000/api/posts?userId=${loggedInUser.username}`)
    .then(response => {
        if (!response.ok) { // 응답 오류 시
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json(); // 응답을 JSON으로 변환
    })
    .then(data => {
        console.log('Received posts:', data.posts); // 디버깅 로그
        const posts = data.posts || []; // 게시물 목록
        posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)); // 최신순 정렬
        posts.forEach(post => {
            const likedBy = post.likedBy || []; // 좋아요 누른 사용자
            const hasLiked = likedBy.includes(loggedInUser.username); // 사용자가 좋아요 눌렀는지
            const postElement = document.createElement('div'); // 새 div 생성
            postElement.className = 'post'; // CSS 클래스 추가
            postElement.innerHTML = `
                ${post.image ? `<img src="http://localhost:3000${post.image}" alt="코디 사진">` : ''} <!-- 이미지 표시 -->
                <h3>${post.userId}</h3> <!-- 작성자 이름 -->
                <h3>${post.title}</h3> <!-- 게시물 제목 -->
                <p>${post.content}</p> <!-- 게시물 내용 -->
                <button class="like-btn" onclick="likePost(this, '${post._id}')" 
                    data-clicked="${hasLiked}"
                    style="background-color: ${hasLiked ? '#ffcccc' : ''}">
                    좋아요 <span>${post.likes || 0}</span> <!-- 좋아요 버튼 -->
                </button>
                <button class="delete-btn" data-post-id="${post._id}">삭제</button> <!-- 삭제 버튼 -->
            `;
            myPostContainer.appendChild(postElement); // 컨테이너에 추가

            const deleteBtn = postElement.querySelector('.delete-btn'); // 삭제 버튼
            deleteBtn.addEventListener('click', () => deletePost(post._id)); // 삭제 함수 연결
        });
    })
    .catch(error => { // 오류 처리
        console.error('Error fetching my posts:', error);
        alert('내 게시물을 불러오는 중 오류가 발생했습니다.');
    });
}

// 이미지 업로드 미리보기 함수
function previewImage() {
    const postImageInput = document.getElementById('post-image'); // 이미지 입력 요소
    const imagePreview = document.getElementById('image-preview'); // 미리보기 요소
    if (postImageInput && imagePreview) { // 요소가 모두 있으면
        postImageInput.addEventListener('change', function(e) { // 파일 선택 시
            const file = e.target.files[0]; // 선택된 파일
            if (file) { // 파일이 있으면
                const reader = new FileReader(); // 파일 읽기 객체
                reader.onload = function(event) { // 파일 읽기 완료 시
                    imagePreview.innerHTML = `<img src="${event.target.result}" alt="미리보기 이미지">`; // 미리보기 표시
                };
                reader.readAsDataURL(file); // 파일을 Data URL로 변환
            } else { // 파일 없으면
                imagePreview.innerHTML = ''; // 미리보기 지우기
            }
        });
    }
}