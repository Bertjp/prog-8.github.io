const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// セッション設定
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false
}));

const db = new sqlite3.Database('./db.sqlite');


// ======================
// ■ ユーザー登録
// ======================
app.post('/register', async (req, res) => {
  const { room_number, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (room_number, password) VALUES (?, ?)`,
    [room_number, hashed],
    (err) => {
      if (err) return res.send("登録失敗");
      res.send("登録成功");
    }
  );
});


// ======================
// ■ ログイン
// ======================
app.post('/login', (req, res) => {
  const { room_number, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE room_number=?`,
    [room_number],
    async (err, user) => {

      if (!user) return res.send("ユーザーなし");

      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.send("パスワード違う");

      // セッション保存
      req.session.user = {
        id: user.id,
        role: user.role
      };

      res.send("ログイン成功");
    }
  );
});


// ======================
// ■ ログインチェック
// ======================
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).send("ログイン必要");
  }
  next();
}


// ======================
// ■ 管理者チェック
// ======================
function requireAdmin(req, res, next) {
  if (req.session.user.role !== 'admin') {
    return res.status(403).send("権限なし");
  }
  next();
}


// ======================
// ■ 予約API（ログイン必須）
// ======================
app.post('/reserve', requireLogin, (req, res) => {
  const { spot, date, time } = req.body;
  const user_id = req.session.user.id;

  // 重複チェック
  db.get(
    `SELECT * FROM reservations
     WHERE parking_spot=? AND date=? AND time_slot=? AND status='active'`,
    [spot, date, time],
    (err, row) => {

      if (row) return res.send("すでに予約あり");

      db.run(
        `INSERT INTO reservations (user_id, parking_spot, date, time_slot, status)
         VALUES (?, ?, ?, ?, 'active')`,
        [user_id, spot, date, time],
        () => res.send("予約完了")
      );
    }
  );
});


// ======================
// ■ ログアウト
// ======================
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.send("ログアウトしました");
});


app.listen(3000, () => console.log("Server started"));