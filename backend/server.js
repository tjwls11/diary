require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3011;
const saltRounds = 10;
const secretKey = process.env.SECRET_KEY || 'default_secret';

// CORS 설정
const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL 연결 설정
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'tjwls100',
  database: process.env.DB_NAME || 'souldiary'
};

const pool = mysql.createPool(dbConfig);

// JWT 인증 미들웨어
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Authorization: Bearer <token>
  
  if (!token) return res.sendStatus(401); // 인증되지 않음

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      console.error('JWT 인증 실패:', err);
      return res.sendStatus(403); // 금지됨
    }
    req.user = user;
    next();
  });
};

// 기본 라우트 설정
app.get('/', (req, res) => {
  res.send('<h1>서버에 오신 것을 환영합니다!</h1><p>서버가 정상적으로 실행되고 있습니다.</p>');
});

// 회원가입 엔드포인트
app.post('/signup', async (req, res) => {
  const { name, user_id, password } = req.body;

  if (!name || !user_id || !password) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해 주세요.' });
  }

  try {
    const hash = await bcrypt.hash(password, saltRounds);
    await pool.query('INSERT INTO `user` (`name`, `user_id`, `password`) VALUES (?, ?, ?)', [name, user_id, hash]);
    res.status(201).json({ isSuccess: true, message: '회원 가입 성공' });
  } catch (err) {
    console.error('회원 가입 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 로그인 엔드포인트
app.post('/login', async (req, res) => {
  const { user_id, password } = req.body;

  if (!user_id || !password) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해 주세요.' });
  }

  try {
    const [results] = await pool.query('SELECT * FROM `user` WHERE `user_id` = ?', [user_id]);

    if (results.length === 0) {
      return res.status(401).json({ isSuccess: false, message: '사용자를 찾을 수 없습니다' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ isSuccess: false, message: '잘못된 비밀번호' });
    }

    const token = jwt.sign({ user_id: user.user_id, name: user.name }, secretKey, { expiresIn: '1h' });
    res.json({ isSuccess: true, message: '로그인 성공', token, user: { user_id: user.user_id, name: user.name } });
  } catch (err) {
    console.error('서버 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 사용자 정보 조회 엔드포인트
app.get('/user-info', authenticateToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT `name`, `user_id`, `coin` FROM `user` WHERE `user_id` = ?', [req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: '사용자를 찾을 수 없습니다' });
    }

    res.json({ user: results[0] });
  } catch (err) {
    console.error('사용자 정보 조회 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 비밀번호 변경 엔드포인트
app.post('/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해 주세요' });
  }

  try {
    const [results] = await pool.query('SELECT `password` FROM `user` WHERE `user_id` = ?', [req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: '사용자를 찾을 수 없습니다' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(401).json({ isSuccess: false, message: '현재 비밀번호가 올바르지 않습니다' });
    }

    const hash = await bcrypt.hash(newPassword, saltRounds);
    await pool.query('UPDATE `user` SET `password` = ? WHERE `user_id` = ?', [hash, req.user.user_id]);
    res.json({ isSuccess: true, message: '비밀번호가 성공적으로 변경되었습니다' });
  } catch (err) {
    console.error('비밀번호 변경 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 스티커 관련

// 스티커 목록 조회 엔드포인트
app.get('/get-user-stickers', authenticateToken, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT s.sticker_id, s.name, s.image_url, s.price FROM stickers s INNER JOIN user_stickers us ON s.sticker_id = us.sticker_id WHERE us.user_id = ?',
      [req.user.user_id]
    );
    console.log('Stickers results:', results);
    res.json({ stickers: results, isSuccess: true });
  } catch (err) {
    console.error('스티커 목록 조회 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});



// 스티커 구매 엔드포인트
app.post('/buy-sticker', authenticateToken, async (req, res) => {
  const { sticker_id } = req.body;

  if (!sticker_id) {
    return res.status(400).json({ isSuccess: false, message: '스티커 ID가 필요합니다.' });
  }

  try {
    const [checkResults] = await pool.query('SELECT * FROM `user_stickers` WHERE `user_id` = ? AND `sticker_id` = ?', [req.user.user_id, sticker_id]);
    if (checkResults.length > 0) {
      return res.status(400).json({ isSuccess: false, message: '이미 이 스티커를 소유하고 있습니다.' });
    }

    await pool.query('INSERT INTO `user_stickers` (`user_id`, `sticker_id`) VALUES (?, ?)', [req.user.user_id, sticker_id]);
    res.status(201).json({ isSuccess: true, message: '스티커가 성공적으로 구매되었습니다.' });
  } catch (err) {
    console.error('스티커 구매 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 캘린더 관련
// 무드 범위 조회 엔드포인트
app.get('/get-mood-range', authenticateToken, async (req, res) => {
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ isSuccess: false, message: '시작 날짜와 종료 날짜가 필요합니다.' });
  }

  try {
    const [results] = await pool.query(
      'SELECT `date`, `color` FROM `calendar` WHERE `date` BETWEEN ? AND ? AND `user_id` = ?',
      [startDate, endDate, req.user.user_id]
    );
    res.json({ moods: results });
  } catch (err) {
    console.error('무드 범위 조회 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 무드 색상 설정 엔드포인트
app.post('/set-mood', authenticateToken, async (req, res) => {
  const { date, color } = req.body;

  if (!date || !color) {
    return res.status(400).json({ isSuccess: false, message: '날짜와 색상 정보가 필요합니다.' });
  }

  try {
    await pool.query(
      'INSERT INTO `calendar` (`user_id`, `date`, `color`) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE `color` = VALUES(`color`)',
      [req.user.user_id, date, color]
    );
    res.status(200).json({ isSuccess: true, message: '무드 색상이 성공적으로 설정되었습니다.' });
  } catch (err) {
    console.error('무드 색상 설정 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 스티커 캘린더 추가 엔드포인트
app.post('/add-to-calendar', authenticateToken, async (req, res) => {
  const { date, color, sticker_id } = req.body;

  if (!date || !color || !sticker_id) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해 주세요.' });
  }

  try {
    await pool.query(
      'INSERT INTO calendar (user_id, date, color, sticker_id) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE color = VALUES(color), sticker_id = VALUES(sticker_id)',
      [req.user.user_id, date, color, sticker_id]
    );
    res.status(201).json({ isSuccess: true, message: '캘린더에 스티커가 성공적으로 추가되었습니다.' });
  } catch (err) {
    console.error('캘린더에 스티커 추가 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 다이어리 관련
// 다이어리 목록 조회 엔드포인트
app.get('/get-diaries', authenticateToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT * FROM `diary` WHERE `user_id` = ?', [req.user.user_id]);
    res.json({ diaries: results });
  } catch (err) {
    console.error('다이어리 목록 조회 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 다이어리 추가 엔드포인트
app.post('/add-diary', authenticateToken, async (req, res) => {
  const { date, title, content, one } = req.body;

  if (!date || !title || !content) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해 주세요.' });
  }

  try {
    const [result] = await pool.query('INSERT INTO `diary` (`user_id`, `date`, `title`, `content`, `one`) VALUES (?, ?, ?, ?, ?)', [req.user.user_id, date, title, content, one]);
    res.status(201).json({ isSuccess: true, message: '일기가 성공적으로 추가되었습니다', diaryId: result.insertId });
  } catch (err) {
    console.error('일기 추가 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 일기 상세 조회 엔드포인트
app.get('/get-diary/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [results] = await pool.query('SELECT * FROM `diary` WHERE `id` = ? AND `user_id` = ?', [id, req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: '일기를 찾을 수 없습니다.' });
    }

    res.json({ isSuccess: true, diary: results[0] });
  } catch (err) {
    console.error('일기 조회 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류' });
  }
});

// 서버 시작
app.listen(port, () => {
  console.log(`서버가 포트 ${port}에서 실행 중입니다.`);
});
