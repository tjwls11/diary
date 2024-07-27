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
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.sendStatus(401); // 인증되지 않음

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      console.error('JWT verification failed:', err);
      return res.sendStatus(403); // 금지됨
    }
    req.user = user;
    next();
  });
};

// 기본 라우트 설정
app.get('/', (req, res) => {
  res.send('<h1>Welcome to the Server!</h1><p>The server is up and running.</p>');
});

// 회원가입 엔드포인트
app.post('/signup', async (req, res) => {
  const { name, user_id, password } = req.body;

  if (!name || !user_id || !password) {
    return res.status(400).json({ isSuccess: false, message: 'All fields are required.' });
  }

  try {
    const hash = await bcrypt.hash(password, saltRounds);
    await pool.query('INSERT INTO `user` (`name`, `user_id`, `password`) VALUES (?, ?, ?)', [name, user_id, hash]);
    res.status(201).json({ isSuccess: true, message: 'User created successfully' });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 로그인 엔드포인트
app.post('/login', async (req, res) => {
  const { user_id, password } = req.body;

  if (!user_id || !password) {
    return res.status(400).json({ isSuccess: false, message: 'All fields are required.' });
  }

  try {
    const [results] = await pool.query('SELECT * FROM `user` WHERE `user_id` = ?', [user_id]);

    if (results.length === 0) {
      return res.status(401).json({ isSuccess: false, message: 'User not found' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ isSuccess: false, message: 'Invalid password' });
    }

    const token = jwt.sign({ user_id: user.user_id, name: user.name }, secretKey, { expiresIn: '1h' });
    res.json({ isSuccess: true, message: 'Login successful', token, user: { user_id: user.user_id, name: user.name } });
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 사용자 정보 조회 엔드포인트
app.get('/user-info', authenticateToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT `name`, `user_id`, `coin` FROM `user` WHERE `user_id` = ?', [req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'User not found' });
    }

    res.json({ user: results[0] });
  } catch (err) {
    console.error('Error fetching user info:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 비밀번호 변경 엔드포인트
app.post('/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ isSuccess: false, message: 'All fields are required' });
  }

  try {
    const [results] = await pool.query('SELECT `password` FROM `user` WHERE `user_id` = ?', [req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'User not found' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(401).json({ isSuccess: false, message: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, saltRounds);
    await pool.query('UPDATE `user` SET `password` = ? WHERE `user_id` = ?', [hash, req.user.user_id]);
    res.json({ isSuccess: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 다이어리 추가 엔드포인트
app.post('/add-diary', authenticateToken, async (req, res) => {
  const { date, title, content, one } = req.body;

  if (!date || !title || !content) {
    return res.status(400).json({ isSuccess: false, message: 'All fields are required.' });
  }

  try {
    await pool.query('INSERT INTO `diary` (`user_id`, `date`, `title`, `content`, `one`) VALUES (?, ?, ?, ?, ?)', [req.user.user_id, date, title, content, one]);
    res.status(201).json({ isSuccess: true, message: 'Diary added successfully' });
  } catch (err) {
    console.error('Error adding diary:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 다이어리 목록 조회 엔드포인트
app.get('/get-diaries', authenticateToken, async (req, res) => {
  try {
    const [results] = await pool.query('SELECT `id`, `title`, `date` FROM `diary` WHERE `user_id` = ?', [req.user.user_id]);
    res.json({ diaries: results });
  } catch (err) {
    console.error('Error fetching diaries:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 다이어리 상세 조회 엔드포인트
app.get('/get-diary/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ isSuccess: false, message: 'Diary id is required' });
  }

  try {
    const [results] = await pool.query('SELECT * FROM `diary` WHERE `id` = ? AND `user_id` = ?', [id, req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'Diary not found or you are not authorized to view it' });
    }

    res.json({ diary: results[0] });
  } catch (err) {
    console.error('Error fetching diary:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 다이어리 삭제 엔드포인트
app.delete('/delete-diary/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ isSuccess: false, message: 'Diary id is required.' });
  }

  try {
    const [results] = await pool.query('DELETE FROM `diary` WHERE `id` = ? AND `user_id` = ?', [id, req.user.user_id]);

    if (results.affectedRows === 0) {
      return res.status(404).json({ isSuccess: false, message: 'Diary not found or you are not authorized to delete it' });
    }

    res.json({ isSuccess: true, message: 'Diary deleted successfully' });
  } catch (err) {
    console.error('Error deleting diary:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 무드 트래커 기능 엔드포인트
// 감정 상태 색상 저장
app.post('/set-mood', authenticateToken, async (req, res) => {
  const { date, color } = req.body;

  if (!date || !color) {
    return res.status(400).json({ isSuccess: false, message: 'Date and color are required.' });
  }

  try {
    await pool.query('INSERT INTO `calendar` (`user_id`, `date`, `color`) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE `color` = ?', [req.user.user_id, date, color, color]);
    res.status(201).json({ isSuccess: true, message: 'Mood color set successfully' });
  } catch (err) {
    console.error('Error setting mood color:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 무드 트래커 기능 엔드포인트
// 특정 날짜의 감정 상태 색상 조회
app.get('/get-mood/:date', authenticateToken, async (req, res) => {
  const { date } = req.params;

  if (!date) {
    return res.status(400).json({ isSuccess: false, message: 'Date is required.' });
  }

  try {
    const [results] = await pool.query('SELECT `color` FROM `calendar` WHERE `user_id` = ? AND `date` = ?', [req.user.user_id, date]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'Mood color not found for this date' });
    }

    res.json({ isSuccess: true, color: results[0].color });
  } catch (err) {
    console.error('Error fetching mood color:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

// 특정 기간 동안의 감정 상태 색상 조회
app.get('/get-mood-range', authenticateToken, async (req, res) => {
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ isSuccess: false, message: 'Start date and end date are required.' });
  }

  // 날짜 형식 검증
  const isValidDate = (date) => !isNaN(Date.parse(date));
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return res.status(400).json({ isSuccess: false, message: 'Invalid date format.' });
  }

  try {
    const [results] = await pool.query('SELECT `date`, `color` FROM `calendar` WHERE `user_id` = ? AND `date` BETWEEN ? AND ?', [req.user.user_id, startDate, endDate]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'No mood colors found for the given range.' });
    }

    res.json({ isSuccess: true, moods: results });
  } catch (err) {
    console.error('Error fetching mood range:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
