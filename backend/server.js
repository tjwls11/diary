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

// 미들웨어 설정
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL 연결 설정
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'tjwls100',
  database: process.env.DB_NAME || 'souldiary'
};

// JWT 인증 미들웨어
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Assuming Bearer token

  if (!token) {
    return res.status(401).json({ isSuccess: false, message: 'Unauthorized' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ isSuccess: false, message: 'Forbidden' });
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
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해주세요.' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const hash = await bcrypt.hash(password, saltRounds);

    await connection.execute(
      'INSERT INTO `user` (`name`, `user_id`, `password`) VALUES (?, ?, ?)',
      [name, user_id, hash]
    );
    res.status(201).json({ isSuccess: true, message: '사용자 생성 성공' });
  } catch (err) {
    console.error('사용자 생성 실패:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

// 로그인 엔드포인트
app.post('/login', async (req, res) => {
  const { user_id, password } = req.body;

  if (!user_id || !password) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해주세요.' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const [results] = await connection.execute('SELECT * FROM `user` WHERE `user_id` = ?', [user_id]);

    if (results.length === 0) {
      return res.status(401).json({ isSuccess: false, message: '사용자 없음' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ isSuccess: false, message: '비밀번호 불일치' });
    }

    const token = jwt.sign({ user_id: user.user_id, name: user.name }, secretKey, { expiresIn: '1h' });
    res.json({ isSuccess: true, message: '로그인 성공', token, user: { user_id: user.user_id, name: user.name } });
  } catch (err) {
    console.error('서버 오류:', err);
    res.status(500).json({ isSuccess: false, message: '서버 오류: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

// 사용자 정보 조회 엔드포인트
app.get('/user-info', authenticateToken, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const [results] = await connection.execute('SELECT `name`, `user_id`, `coin` FROM `user` WHERE `user_id` = ?', [req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'User not found' });
    }

    res.json({ user: results[0] });
  } catch (err) {
    console.error('Error fetching user info:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

// 비밀번호 변경 엔드포인트
app.post('/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ isSuccess: false, message: 'All fields are required' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const [results] = await connection.execute('SELECT `password` FROM `user` WHERE `user_id` = ?', [req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'User not found' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(401).json({ isSuccess: false, message: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, saltRounds);
    await connection.execute('UPDATE `user` SET `password` = ? WHERE `user_id` = ?', [hash, req.user.user_id]);
    res.json({ isSuccess: true, message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

// 다이어리 추가 엔드포인트
app.post('/add-diary', authenticateToken, async (req, res) => {
  const { date, title, content, one } = req.body;

  if (!date || !title || !content) {
    return res.status(400).json({ isSuccess: false, message: '모든 필드를 입력해주세요.' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    await connection.execute(
      'INSERT INTO `diary` (`user_id`, `date`, `title`, `content`, `one`) VALUES (?, ?, ?, ?, ?)',
      [req.user.user_id, date, title, content, one]
    );
    res.status(201).json({ isSuccess: true, message: '일기 추가 성공' });
  } catch (err) {
    console.error('Error adding diary:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

// 다이어리 목록 조회 엔드포인트
app.get('/get-diaries', authenticateToken, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    // 현재 요청하는 사용자의 일기만 조회
    const [results] = await connection.execute(
      'SELECT `id`, `title`, `date` FROM `diary` WHERE `user_id` = ?',
      [req.user.user_id]
    );
    res.json({ diaries: results });
  } catch (err) {
    console.error('Error fetching diaries:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

// 다이어리 상세 조회 엔드포인트
app.get('/get-diary/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ isSuccess: false, message: 'Diary id is required' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    // 특정 일기 조회
    const [results] = await connection.execute(
      'SELECT * FROM `diary` WHERE `id` = ? AND `user_id` = ?',
      [id, req.user.user_id]
    );

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'Diary not found or you are not authorized to view it' });
    }

    res.json({ diary: results[0] });
  } catch (err) {
    console.error('Error fetching diary:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});


// 다이어리 삭제 엔드포인트
app.delete('/delete-diary/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ isSuccess: false, message: 'id를 제공해야 합니다.' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute('DELETE FROM `diary` WHERE `id` = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ isSuccess: false, message: '일기를 찾을 수 없습니다.' });
    }

    res.json({ isSuccess: true, message: '일기 삭제 성공' });
  } catch (err) {
    console.error('Error deleting diary:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

// 날짜별 한 줄 요약 가져오기 엔드포인트
app.get('/api/notes', async (req, res) => {
  const { date } = req.query;

  if (!date) {
    return res.status(400).json({ isSuccess: false, message: 'date를 제공해야 합니다.' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    const [results] = await connection.execute('SELECT `one` FROM `diary` WHERE `date` = ? AND `user_id` = ?', [date, req.user.user_id]);

    if (results.length === 0) {
      return res.status(404).json({ isSuccess: false, message: 'Note not found' });
    }

    res.json({ one: results[0].one });
  } catch (err) {
    console.error('Error fetching note:', err);
    res.status(500).json({ isSuccess: false, message: 'Server error: ' + err.message });
  } finally {
    if (connection) connection.end();
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
