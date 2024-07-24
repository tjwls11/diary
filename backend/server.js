const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3011;
const saltRounds = 10;
const secretKey = process.env.SECRET_KEY || 'default_secret'; // 환경 변수로 관리

// 미들웨어 설정
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL 연결 설정
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'tjwls100',
  database: 'souldiary'
};

// 기본 라우트 설정
app.get('/', (req, res) => {
  res.send('<h1>Welcome to the Server!</h1><p>The server is up and running.</p>');
});

// 회원가입 엔드포인트
app.post('/signup', async (req, res) => {
  const { name, user_id, password } = req.body;

  if (!name || !user_id || !password) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해주세요.' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const hash = await bcrypt.hash(password, saltRounds);

    const [result] = await connection.execute(
      'INSERT INTO user (name, user_id, password) VALUES (?, ?, ?)',
      [name, user_id, hash]
    );
    await connection.end();
    res.status(201).json({ isSuccess: true, message: '사용자 생성 성공' });
  } catch (err) {
    console.error('사용자 생성 실패:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류: ' + err.message });
  }
});

// 로그인 엔드포인트
app.post('/login', async (req, res) => {
  const { user_id, password } = req.body;

  if (!user_id || !password) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해주세요.' });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [results] = await connection.execute('SELECT * FROM user WHERE user_id = ?', [user_id]);

    if (results.length === 0) {
      await connection.end();
      return res.status(401).json({ isSuccess: false, message: '사용자 없음' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      await connection.end();
      return res.status(401).json({ isSuccess: false, message: '비밀번호 불일치' });
    }

    // 로그인 성공 시 JWT 토큰 발급
    const token = jwt.sign({ user_id: user.user_id, name: user.name }, secretKey, { expiresIn: '1h' });
    await connection.end();
    res.json({ isSuccess: true, message: '로그인 성공', token, user: { user_id: user.user_id, name: user.name } });
  } catch (err) {
    console.error('서버 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류: ' + err.message });
  }
});

// 유저 정보 엔드포인트
app.get('/user-info', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Assuming Bearer token

  if (!token) {
    return res.status(401).json({ isSuccess: false, message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    const user_id = decoded.user_id;

    const connection = await mysql.createConnection(dbConfig);
    const [results] = await connection.execute('SELECT user_id, name, coin FROM user WHERE user_id = ?', [user_id]);
    connection.end();

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'User not found' });
    }

    res.json({ user: results[0] });
  } catch (err) {
    console.error('Error fetching user data:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error' });
  }
});

// 서버 시작
app.listen(port, () => {
  console.log(`서버가 http://localhost:${port} 에서 실행 중입니다.`);
});
