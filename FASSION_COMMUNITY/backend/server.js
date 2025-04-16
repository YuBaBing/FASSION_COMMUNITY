// 필요한 모듈 가져오기
const express = require('express'); // 웹 서버를 만들기 위한 도구(프레임워크)
const mongoose = require('mongoose'); // MongoDB 데이터베이스를 쉽게 관리해주는 도구
const multer = require('multer'); // 사용자가 업로드한 파일(예: 이미지)을 처리하는 도구
const cors = require('cors'); // 프론트엔드와 백엔드가 서로 통신할 수 있게 허용해주는 도구
const path = require('path'); // 파일 경로를 쉽게 다루기 위한 도구
const fs = require('fs'); // 동기 API용
const fsPromises = require('fs').promises; // 파일 시스템 작업(예: 폴더 만들기)을 위한 도구
const bcrypt = require('bcrypt'); // 비밀번호를 안전하게 암호화(해시)하는 도구
const jwt = require('jsonwebtoken'); // 사용자 인증을 위한 토큰(JWT)을 만들고 확인하는 도구
const cookieParser = require('cookie-parser'); // 쿠키를 쉽게 읽고 설정하는 도구

const app = express(); // Express 앱을 생성 (웹 서버 시작점)

//mongodb atlas 데이터 연결
require('dotenv').config();


mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));



// 미들웨어 설정: 서버가 요청을 처리할 때 자동으로 실행되는 기능들
app.use(cors({
    origin: ['http://localhost:8080'], // 프론트엔드 주소(예: live-server) 허용
    credentials: true // 쿠키를 주고받을 수 있도록 설정
})); // CORS 설정: 프론트엔드와 백엔드 간 통신 허용
app.use(express.json()); // 요청에 포함된 JSON 데이터를 자동으로 해석
app.use(cookieParser()); // 요청에 포함된 쿠키를 자동으로 읽음
app.use('/uploads', express.static(path.join(__dirname, 'Uploads'))); // '/uploads'로 요청 오면 'Uploads' 폴더의 파일(예: 이미지) 제공

// MongoDB 연결: 데이터베이스와 서버 연결
mongoose.connect('mongodb://localhost/social_media') // 로컬 MongoDB의 'social_media' 데이터베이스에 연결
    .then(() => console.log('MongoDB connected')) // 연결 성공 시 메시지 출력
    .catch(err => console.error('MongoDB connection error:', err)); // 연결 실패 시 오류 출력

// Multer 설정: 업로드된 파일(예: 이미지)을 어떻게 저장할지 정의
const storage = multer.diskStorage({
    // 파일을 저장할 폴더 설정
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'Uploads'); // 'Uploads' 폴더 경로 (예: backend/Uploads)
        if (!fs.existsSync(uploadPath)) { // 폴더가 없으면
            fs.mkdirSync(uploadPath, { recursive: true }); // 폴더를 새로 만듦
        }
        cb(null, uploadPath); // 파일을 저장할 경로로 'Uploads' 지정
    },
    // 저장할 파일 이름 설정
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname); // 파일 확장자 추출 (예: .png, .jpg)
        // 파일 이름에서 특수문자 제거, 최대 20자
        const baseName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9.\-_]/g, '').slice(0, 20);
        cb(null, `${Date.now()}-${baseName}${ext}`); // 고유 이름 생성 (예: 1744202434083-test.png)
    }
});
const upload = multer({ storage }); // Multer 설정 적용

// 사용자 스키마: MongoDB에서 사용자 데이터를 어떻게 저장할지 정의
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true }, // 사용자 이름 (중복 불가, 필수)
    password: { type: String, required: true }, // 암호화된 비밀번호 (필수)
    createdAt: { type: Date, default: Date.now } // 가입 날짜 (기본값: 현재 시간)
});
const User = mongoose.model('User', userSchema); // 'User'라는 이름으로 데이터 모델 생성

// 게시물 스키마: MongoDB에서 게시물 데이터를 어떻게 저장할지 정의
const postSchema = new mongoose.Schema({
    userId: String, // 게시물을 작성한 사용자의 ID (username)
    title: String, // 게시물 제목
    content: String, // 게시물 내용
    image: String, // 업로드된 이미지 경로 (예: /uploads/파일명)
    createdAt: Date, // 게시물 작성 날짜
    likes: { type: Number, default: 0 }, // 좋아요 수 (기본값: 0)
    likedBy: [String] // 좋아요를 누른 사용자 이름 목록
});
const Post = mongoose.model('Post', postSchema); // 'Post'라는 이름으로 데이터 모델 생성

// JWT 검증 미들웨어: 요청에 포함된 쿠키의 토큰을 확인해 사용자가 맞는지 인증
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token; // 요청 쿠키에서 'token' 가져오기
    if (!token) { // 토큰이 없으면
        console.log('Auth failed: No token provided'); // 오류 로그
        return res.status(401).json({ success: false, message: '인증 토큰이 없습니다.' }); // 401 에러 응답
    }
    // 토큰 검증
    jwt.verify(token, 'secret_key', (err, user) => { // 비밀키로 토큰 확인
        if (err) { // 토큰이 잘못되었거나 만료
            console.log('Auth failed: Invalid token', err.message); // 오류 로그
            return res.status(403).json({ success: false, message: '유효하지 않은 토큰입니다.' }); // 403 에러 응답
        }
        req.user = user; // 토큰에서 추출한 사용자 정보(예: { username: "song" })를 요청 객체에 저장
        next(); // 다음 단계(예: API 로직)로 진행
    });
};

// 회원가입 API: 새로운 사용자를 등록
app.post('/api/register', async (req, res) => {
    try {
        console.log('Register request:', req.body); // 요청 데이터 로그
        const { username, password } = req.body; // 요청에서 사용자 이름과 비밀번호 추출
        if (!username || !password) { // 이름 또는 비밀번호가 없으면
            console.log('Register failed: Missing username or password'); // 오류 로그
            return res.status(400).json({ success: false, message: '사용자 이름과 비밀번호를 입력하세요.' }); // 400 에러 응답
        }
        const existingUser = await User.findOne({ username }); // 동일한 사용자 이름 있는지 확인
        if (existingUser) { // 이미 존재하면
            console.log('Register failed: Username already exists', username); // 오류 로그
            return res.status(400).json({ success: false, message: '이미 존재하는 사용자 이름입니다.' }); // 400 에러 응답
        }
        const hashedPassword = await bcrypt.hash(password, 10); // 비밀번호를 안전하게 암호화
        const user = new User({ // 새 사용자 객체 생성
            username, // 사용자 이름
            password: hashedPassword, // 암호화된 비밀번호
            createdAt: new Date() // 현재 시간
        });
        await user.save(); // MongoDB에 사용자 저장
        console.log('User registered:', username); // 성공 로그
        res.json({ success: true, message: '회원가입 성공' }); // 성공 응답
    } catch (error) {
        console.error('Error in /api/register:', error); // 오류 로그
        res.status(500).json({ success: false, message: '서버 오류' }); // 500 에러 응답
    }
});

// 로그인 API: 사용자 인증 후 JWT 토큰을 HttpOnly 쿠키로 저장
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login request:', req.body); // 요청 데이터 로그
        const { username, password } = req.body; // 사용자 이름과 비밀번호 추출
        if (!username || !password) { // 이름 또는 비밀번호가 없으면
            console.log('Login failed: Missing username or password'); // 오류 로그
            return res.status(400).json({ success: false, message: '사용자 이름과 비밀번호를 입력하세요.' }); // 400 에러 응답
        }
        const user = await User.findOne({ username }); // 사용자 이름으로 DB 조회
        if (!user) { // 사용자가 없으면
            console.log('Login failed: User not found', username); // 오류 로그
            return res.status(401).json({ success: false, message: '사용자를 찾을 수 없습니다.' }); // 401 에러 응답
        }
        const isMatch = await bcrypt.compare(password, user.password); // 입력된 비밀번호와 DB 비밀번호 비교
        if (!isMatch) { // 비밀번호가 틀리면
            console.log('Login failed: Incorrect password', username); // 오류 로그
            return res.status(401).json({ success: false, message: '비밀번호가 틀렸습니다.' }); // 401 에러 응답
        }
        const token = jwt.sign({ username: user.username }, 'secret_key', { expiresIn: '1h' }); // JWT 토큰 생성 (1시간 유효)
        res.cookie('token', token, { // 토큰을 HttpOnly 쿠키로 저장
            httpOnly: true, // 자바스크립트로 접근 못하게 (XSS 방지)
            secure: false, // 로컬 테스트용 false, 배포 시 true로 변경 (HTTPS 필요)
            maxAge: 3600000, // 쿠키 유효 기간: 1시간 (밀리초)
            sameSite: 'Lax' // SameSite 명시
        });
        console.log('Login success:', username,'Token:', token); // 성공 로그
        res.json({ success: true, username: user.username }); // 사용자 이름 응답 (클라이언트 UI용)
    } catch (error) {
        console.error('Error in /api/login:', error); // 오류 로그
        res.status(500).json({ success: false, message: '서버 오류' }); // 500 에러 응답
    }
});

// 로그아웃 API: 쿠키에 저장된 토큰 삭제
app.post('/api/logout', (req, res) => {
    res.clearCookie('token'); // 'token' 쿠키 삭제
    console.log('Logout success'); // 성공 로그
    res.json({ success: true, message: '로그아웃 성공' }); // 성공 응답
});

// 게시물 추가 API: 새 게시물 저장 (쿠키 인증 적용)
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        console.log('Request body:', req.body, 'File:', req.file, 'User:', req.user.username); // 요청 데이터와 사용자 로그
        const { title, content } = req.body; // 제목과 내용 추출
        const userId = req.user.username; // 쿠키 토큰에서 사용자 이름 가져옴
        if (!title || !content) { // 제목 또는 내용이 없으면
            console.log('Post failed: Missing required fields'); // 오류 로그
            return res.status(400).json({ success: false, message: '제목과 내용을 입력해주세요.' }); // 400 에러 응답
        }
        const image = req.file ? `/uploads/${req.file.filename}` : ''; // 이미지 있으면 경로 저장, 없으면 빈 문자열
        const newPost = new Post({ // 새 게시물 객체 생성
            userId, // 작성자 ID (토큰에서 가져옴)
            title, // 게시물 제목
            content, // 게시물 내용
            image, // 이미지 경로
            createdAt: new Date(), // 현재 시간
            likes: 0, // 초기 좋아요 0
            likedBy: [] // 초기 좋아요 사용자 없음
        });
        await newPost.save(); // MongoDB에 게시물 저장
        console.log('Post created:', { userId, title }); // 성공 로그
        res.json({ success: true, post: newPost }); // 저장된 게시물 응답
    } catch (error) {
        console.error('Error in /api/posts POST:', error); // 오류 로그
        res.status(500).json({ success: false, message: '서버 오류', error: error.message }); // 500 에러 응답
    }
});

// 게시물 조회 API: 모든 게시물 또는 특정 사용자 게시물 조회 (인증 불필요)
app.get('/api/posts', async (req, res) => {
    try {
        console.log('Received GET request to /api/posts', req.query); // 요청 쿼리 로그
        const page = parseInt(req.query.page) || 1; // 페이지 번호 (기본: 1)
        const limit = parseInt(req.query.limit) || 4; // 한 페이지당 게시물 수 (기본: 4)
        const userId = req.query.userId; // 특정 사용자 게시물 조회 시 사용
        const skip = (page - 1) * limit; // 건너뛸 게시물 수 (페이지네이션)
        const query = userId ? { userId } : {}; // userId 있으면 특정 사용자, 없으면 전체
        const posts = await Post.find(query) // 조건에 맞는 게시물 조회
            .sort({ createdAt: -1 }) // 최신순 정렬
            .skip(skip) // 페이지네이션 시작점
            .limit(limit); // 최대 게시물 수
        const total = await Post.countDocuments(query); // 조건에 맞는 전체 게시물 수
        console.log('Posts fetched:', posts.length); // 조회된 게시물 수 로그
        res.json({ posts, hasMore: skip + posts.length < total }); // 게시물과 더 불러올 수 있는지 여부 응답
    } catch (error) {
        console.error('Error in /api/posts GET:', error); // 오류 로그
        res.status(500).json({ success: false, message: '게시물 조회 중 오류가 발생했습니다.' }); // 500 에러 응답
    }
});

// 좋아요 API: 게시물에 좋아요 추가/제거 (쿠키 인증 적용)
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        console.log('Like request:', req.params.id, 'User:', req.user.username); // 요청과 사용자 로그
        const postId = req.params.id; // 게시물 ID (URL에서 가져옴)
        const username = req.user.username; // 쿠키 토큰에서 사용자 이름 가져옴
        const post = await Post.findById(postId); // 게시물 조회
        if (!post) { // 게시물이 없으면
            console.log('Like failed: Post not found', postId); // 오류 로그
            return res.status(404).json({ success: false, message: '게시물을 찾을 수 없습니다.' }); // 404 에러 응답
        }
        const hasLiked = post.likedBy.includes(username); // 사용자가 이미 좋아요 눌렀는지 확인
        if (hasLiked) { // 이미 눌렀으면
            post.likes -= 1; // 좋아요 수 감소
            post.likedBy = post.likedBy.filter(user => user !== username); // 사용자 제거
            console.log('Like removed:', username, postId); // 성공 로그
        } else { // 안 눌렀으면
            post.likes += 1; // 좋아요 수 증가
            post.likedBy.push(username); // 사용자 추가
            console.log('Like added:', username, postId); // 성공 로그
        }
        await post.save(); // 변경사항 저장
        res.json({ success: true, post }); // 업데이트된 게시물 응답
    } catch (error) {
        console.error('Error in /api/posts/:id/like:', error); // 오류 로그
        res.status(500).json({ success: false, message: '좋아요 처리 중 오류가 발생했습니다.' }); // 500 에러 응답
    }
});

// 게시물 삭제 API: 게시물 삭제 (쿠키 인증 적용)
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        console.log('Delete request:', req.params.id, 'User:', req.user.username); // 요청과 사용자 로그
        const postId = req.params.id; // 게시물 ID (URL에서 가져옴)
        const username = req.user.username; // 쿠키 토큰에서 사용자 이름 가져옴
        const post = await Post.findById(postId); // 게시물 조회
        if (!post) { // 게시물이 없으면
            console.log('Delete failed: Post not found', postId); // 오류 로그
            return res.status(404).json({ success: false, message: '게시물을 찾을 수 없습니다.' }); // 404 에러 응답
        }
        if (post.userId !== username) { // 게시물 작성자가 아니면
            console.log('Delete failed: Unauthorized', username, postId); // 오류 로그
            return res.status(403).json({ success: false, message: '본인이 작성한 게시물만 삭제할 수 있습니다.' }); // 403 에러 응답
        }
        // 이미지 파일 삭제
        if (post.image) { // 게시물에 이미지가 있으면
            const imagePath = path.join(__dirname, post.image); // 예: backend/Uploads/12345-image.jpg
            try {
                await fsPromises.unlink(imagePath); // 파일 삭제
                console.log('이미지 삭제됨:', imagePath);
            } catch (err) {
                console.error('이미지 삭제 실패:', err); // 파일이 없거나 에러 발생 시
            }
        }
        await Post.deleteOne({ _id: postId }); // DB에서 게시물 삭제
        console.log('Post deleted:', postId, username); // 성공 로그
        res.json({ success: true, message: '게시물이 삭제되었습니다.' }); // 성공 응답
    } catch (error) {
        console.error('Error in /api/posts/:id DELETE:', error); // 오류 로그
        res.status(500).json({ success: false, message: '삭제 중 오류가 발생했습니다.' }); // 500 에러 응답
    }
});
// 서버 실행
const PORT = 3000; // 서버가 사용할 포트 번호
app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); // 서버 시작, 포트에서 실행 중 메시지 출력