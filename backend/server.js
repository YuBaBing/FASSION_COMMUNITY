// 필요한 모듈 가져오기
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const cors = require('cors');

app.use(cors({
    origin: ['https://www.fcstest.shop'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type'],
    credentials: true // 쿠키 사용 시 필요
}));
// 요청 로깅 미들웨어
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// 미들웨어 설정
app.use(express.static(path.join(__dirname, '../index'))); // '/index' 디렉토리의 정적 파일 제공
app.use(express.json()); // 요청에 포함된 JSON 데이터를 자동으로 해석
app.use(cookieParser()); // 요청에 포함된 쿠키를 자동으로 읽음
app.use('/uploads', express.static(path.join(__dirname, 'Uploads'))); // '/uploads'로 요청 오면 'Uploads' 폴더의 파일 제공

// 루트 경로에서 home.html 제공
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../index', 'logs.html')));


// MongoDB 연결 함수
const connectDB = async () => {
    try {
        if (mongoose.connection.readyState === 0) {
            await mongoose.connect('mongodb://localhost:27017/social_media');
            console.log('MongoDB Connected');
        } else {
            console.log('MongoDB already connected');
        }
    } catch (err) {
        console.error('MongoDB connection error: ', err);
        process.exit(1);
    }
};

// Multer 설정: 업로드된 파일(예: 이미지)을 어떻게 저장할지 정의
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'Uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const baseName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9.\-_]/g, '').slice(0, 20);
        cb(null, `${Date.now()}-${baseName}${ext}`);
    }
});
const upload = multer({ storage });

// 사용자 스키마
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// 게시물 스키마
const postSchema = new mongoose.Schema({
    userId: String,
    title: String,
    content: String,
    image: String,
    createdAt: Date,
    likes: { type: Number, default: 0 },
    likedBy: [String]
});
const Post = mongoose.model('Post', postSchema);


// JWT 검증 미들웨어: 요청에 포함된 쿠키의 토큰을 확인해 사용자가 맞는지 인증
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        console.log('Auth failed: No token provided');
        return res.status(401).json({ success: false, message: '인증 토큰이 없습니다.' });
    }
    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) {
            console.log('Auth failed: Invalid token', err.message);
            return res.status(403).json({ success: false, message: '유효하지 않은 토큰입니다.' });
        }
        req.user = user;
        next();
    });
};

// 회원가입 API
app.post('/api/register', async (req, res) => {
    try {
        console.log('Register request:', req.body);
        const { username, password } = req.body;
        if (!username || !password) {
            console.log('Register failed: Missing username or password');
            return res.status(400).json({ success: false, message: '사용자 이름과 비밀번호를 입력하세요.' });
        }
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            console.log('Register failed: Username already exists', username);
            return res.status(400).json({ success: false, message: '이미 존재하는 사용자 이름입니다.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            createdAt: new Date()
        });
        await user.save();
        console.log('User registered:', username);
        res.json({ success: true, message: '회원가입 성공' });
    } catch (error) {
        console.error('Error in /api/register:', error);
        res.status(500).json({ success: false, message: '서버 오류' });
    }
});

// 로그인 API
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login request:', req.body);
        const { username, password } = req.body;
        if (!username || !password) {
            console.log('Login failed: Missing username or password');
            return res.status(400).json({ success: false, message: '사용자 이름과 비밀번호를 입력하세요.' });
        }
        const user = await User.findOne({ username });
        if (!user) {
            console.log('Login failed: User not found', username);
            return res.status(401).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login failed: Incorrect password', username);
            return res.status(401).json({ success: false, message: '비밀번호가 틀렸습니다.' });
        }
        const token = jwt.sign({ username: user.username }, 'secret_key', { expiresIn: '1h' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: true, // https에서만 쿠키 전송
            maxAge: 3600000,
            sameSite: 'Lax'
        });
        console.log('Login success:', username, 'Token:', token);
        res.json({ success: true, username: user.username });
    } catch (error) {
        console.error('Error in /api/login:', error);
        res.status(500).json({ success: false, message: '서버 오류' });
    }
});

// 로그아웃 API
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    console.log('Logout success');
    res.json({ success: true, message: '로그아웃 성공' });
});

// 게시물 추가 API
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        console.log('Request body:', req.body, 'File:', req.file, 'User:', req.user.username);
        const { title, content } = req.body;
        const userId = req.user.username;
        if (!title || !content) {
            console.log('Post failed: Missing required fields');
            return res.status(400).json({ success: false, message: '제목과 내용을 입력해주세요.' });
        }
        const image = req.file ? `/Uploads/${req.file.filename}` : '';
        const newPost = new Post({
            userId,
            title,
            content,
            image,
            createdAt: new Date(),
            likes: 0,
            likedBy: []
        });
        await newPost.save();
        console.log('Post created:', { userId, title });
        res.json({ success: true, post: newPost });
    } catch (error) {
        console.error('Error in /api/posts POST:', error);
        res.status(500).json({ success: false, message: '서버 오류', error: error.message });
    }
});

// 게시물 조회 API
app.get('/api/posts', async (req, res) => {
    try {
        console.log('Received GET request to /api/posts', req.query);
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 4;
        const userId = req.query.userId;
        const skip = (page - 1) * limit;
        const query = userId ? { userId } : {};
        const posts = await Post.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);
        const total = await Post.countDocuments(query);
        console.log('Posts fetched:', posts.length);
        res.json({ posts, hasMore: skip + posts.length < total });
    } catch (error) {
        console.error('Error in /api/posts GET:', error);
        res.status(500).json({ success: false, message: '게시물 조회 중 오류가 발생했습니다.' });
    }
});

// 좋아요 API
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        console.log('Like request:', req.params.id, 'User:', req.user.username);
        const postId = req.params.id;
        const username = req.user.username;
        const post = await Post.findById(postId);
        if (!post) {
            console.log('Like failed: Post not found', postId);
            return res.status(404).json({ success: false, message: '게시물을 찾을 수 없습니다.' });
        }
        const hasLiked = post.likedBy.includes(username);
        if (hasLiked) {
            post.likes -= 1;
            post.likedBy = post.likedBy.filter(user => user !== username);
            console.log('Like removed:', username, postId);
        } else {
            post.likes += 1;
            post.likedBy.push(username);
            console.log('Like added:', username, postId);
        }
        await post.save();
        res.json({ success: true, post });
    } catch (error) {
        console.error('Error in /api/posts/:id/like:', error);
        res.status(500).json({ success: false, message: '좋아요 처리 중 오류가 발생했습니다.' });
    }
});

// 게시물 삭제 API
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        console.log('Delete request:', req.params.id, 'User:', req.user.username);
        const postId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(postId)) {
            console.log('Invalid postId:', postId);
            return res.status(400).json({ success: false, message: '유효하지 않은 게시물 ID입니다.' });
        }
        const username = req.user.username;
        const post = await Post.findById(postId);
        if (!post) {
            console.log('Delete failed: Post not found', postId);
            return res.status(404).json({ success: false, message: '게시물을 찾을 수 없습니다.' });
        }
        if (post.userId !== username) {
            console.log('Delete failed: Unauthorized', username, postId);
            return res.status(403).json({ success: false, message: '본인이 작성한 게시물만 삭제할 수 있습니다.' });
        }
        if (post.image) {
           const imagePath = path.join(__dirname, post.image);
           console.log('삭제 시도 중인 파일 경로:', imagePath);
        if (fs.existsSync(imagePath)) {
                try {
                 await fsPromises.unlink(imagePath);
                console.log('이미지 삭제됨:', imagePath);
        }       catch (err) {
                console.error('이미지 삭제 실패:', err.message);
                console.error('에러 세부사항:', err);
        }
    }
        else {
        console.log('이미지 파일이 존재하지 않습니다:', imagePath);
                }
        }
        await Post.deleteOne({ _id: postId });
        console.log('Post deleted:', postId, username);
        res.json({ success: true, message: '게시물이 삭제되었습니다.' });
    } catch (error) {
        console.error('Error in /api/posts/:id DELETE:', error);
        res.status(500).json({ success: false, message: '삭제 중 오류가 발생했습니다.' });
    }
});
//게시물 수정
app.put('/api/posts/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        console.log('Update request:', req.params.id, 'User:', req.user.username);
        const postId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(postId)) {
            console.log('Invalid postId:', postId);
            return res.status(400).json({ success: false, message: '유효하지 않은 게시물 ID입니다.' });
        }
        const username = req.user.username;
        const post = await Post.findById(postId);
        if (!post) {
            console.log('Update failed: Post not found', postId);
            return res.status(404).json({ success: false, message: '게시물을 찾을 수 없습니다.' });
        }
        if (post.userId !== username) {
            console.log('Update failed: Unauthorized', username, postId);
            return res.status(403).json({ success: false, message: '본인이 작성한 게시물만 수정할 수 있습니다.' });
        }

        const { title, content } = req.body;
        if (!title || !content) {
            console.log('Update failed: Missing required fields');
            return res.status(400).json({ success: false, message: '제목과 내용을 입력해주세요.' });
        }

        // 기존 이미지 삭제 (새 이미지가 업로드된 경우)
        if (req.file && post.image) {
            const oldImagePath = path.join(__dirname, post.image);
            if (fs.existsSync(oldImagePath)) {
                try {
                    await fsPromises.unlink(oldImagePath);
                    console.log('기존 이미지 삭제됨:', oldImagePath);
                } catch (err) {
                    console.error('기존 이미지 삭제 실패:', err.message);
                }
            }
        }

        // 새 이미지 경로 설정
        const image = req.file ? `/Uploads/${req.file.filename}` : post.image;

        // 게시물 업데이트
        post.title = title;
        post.content = content;
        post.image = image;
        await post.save();

        console.log('Post updated:', postId, username);
        res.json({ success: true, message: '게시물이 수정되었습니다.', post });
    } catch (error) {
        console.error('Error in /api/posts/:id PUT:', error);
        res.status(500).json({ success: false, message: '수정 중 오류가 발생했습니다.' });
    }
});

// 서버 시작
const startServer = async () => {
    await connectDB();
    app.listen(3000, '0.0.0.0', () => console.log('Server running on port 3000'));
};

startServer();
