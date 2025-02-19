const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { PDFDocument, rgb } = require('pdf-lib');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET = 'adithya';

// Middleware setup
app.use(cors({
  origin: 'https://digital-sign-app.vercel.app',
  credentials: true,
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads folder exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
  console.log('Created uploads folder');
}

// SQLite Database Setup
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database', err);
  } else {
    console.log('Connected to SQLite database.');
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        passwordHash TEXT
      )
    `);
    db.run(`
      CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        originalName TEXT,
        storagePath TEXT,
        signedPath TEXT,
        status TEXT,
        createdAt TEXT,
        FOREIGN KEY(userId) REFERENCES users(id)
      )
    `);
  }
});

// Multer Setup for Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '_' + file.originalname;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'application/pdf') {
      return cb(new Error('Only PDF files are allowed'));
    }
    cb(null, true);
  }
}).single('document');

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader)
    return res.status(401).json({ message: 'No token provided' });
  const token = authHeader.split(' ')[1];
  if (!token)
    return res.status(401).json({ message: 'Invalid token format' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Auth Endpoints
app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required' });
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err)
      return res.status(500).json({ message: 'Error hashing password' });
    const sql = `INSERT INTO users (email, passwordHash) VALUES (?, ?)`;
    db.run(sql, [email, hash], function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error registering user', error: err.message });
      }
      res.json({ message: 'User registered successfully' });
    });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const sql = `SELECT * FROM users WHERE email = ?`;
  db.get(sql, [email], (err, user) => {
    if (err)
      return res.status(500).json({ message: 'Error fetching user' });
    if (!user)
      return res.status(400).json({ message: 'User not found' });
    bcrypt.compare(password, user.passwordHash, (err, result) => {
      if (err)
        return res.status(500).json({ message: 'Error comparing passwords' });
      if (!result)
        return res.status(401).json({ message: 'Invalid credentials' });
      const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '1h' });
      res.json({ token });
    });
  });
});

// Document Endpoints
app.post('/api/documents/upload', authenticateToken, (req, res) => {
  upload(req, res, (err) => {
    if (err) return res.status(400).json({ message: err.message });
    const sql = `INSERT INTO documents (userId, originalName, storagePath, status, createdAt) VALUES (?, ?, ?, ?, ?)`;
    const params = [
      req.user.id,
      req.file.originalname,
      req.file.filename,
      'unsigned',
      new Date().toISOString()
    ];
    db.run(sql, params, function (error) {
      if (error)
        return res.status(500).json({ message: 'Error saving document info' });
      res.json({ message: 'File uploaded successfully', documentId: this.lastID });
    });
  });
});

app.get('/api/documents', authenticateToken, (req, res) => {
  const sql = `SELECT * FROM documents WHERE userId = ?`;
  db.all(sql, [req.user.id], (err, rows) => {
    if (err)
      return res.status(500).json({ message: 'Error fetching documents' });
    res.json({ documents: rows });
  });
});

app.post('/api/documents/sign-text', authenticateToken, async (req, res) => {
  try {
    const { documentId, textSignature } = req.body;
    if (!documentId || !textSignature) {
      return res.status(400).json({ message: 'Document ID and text signature required' });
    }
    const sql = `SELECT * FROM documents WHERE id = ? AND userId = ?`;
    db.get(sql, [documentId, req.user.id], async (err, doc) => {
      if (err || !doc) return res.status(404).json({ message: 'Document not found' });
      const originalPath = path.join(uploadsDir, doc.storagePath);
      const signedFileName = 'signed_' + doc.storagePath;
      const signedPath = path.join(uploadsDir, signedFileName);
      const existingPdfBytes = fs.readFileSync(originalPath);
      const pdfDoc = await PDFDocument.load(existingPdfBytes);
      const pages = pdfDoc.getPages();
      const lastPage = pages[pages.length - 1];
      const { width } = lastPage.getSize();
      lastPage.drawText(textSignature, {
        x: width - 200,
        y: 50,
        size: 24,
        color: rgb(0, 0, 0)
      });
      const pdfBytes = await pdfDoc.save();
      fs.writeFileSync(signedPath, pdfBytes);
      const updateSql = `UPDATE documents SET signedPath = ?, status = ? WHERE id = ?`;
      db.run(updateSql, [signedFileName, 'signed', documentId], function (error) {
        if (error) return res.status(500).json({ message: 'Error updating document status' });
        res.json({ message: 'Document signed successfully with text signature' });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error signing document with text signature' });
  }
});

app.post('/api/documents/sign', authenticateToken, async (req, res) => {
  try {
    const { documentId, signature } = req.body;
    if (!documentId || !signature)
      return res.status(400).json({ message: 'Document ID and signature required' });
    const sql = `SELECT * FROM documents WHERE id = ? AND userId = ?`;
    db.get(sql, [documentId, req.user.id], async (err, doc) => {
      if (err || !doc) return res.status(404).json({ message: 'Document not found' });
      const originalPath = path.join(uploadsDir, doc.storagePath);
      const signedFileName = 'signed_' + doc.storagePath;
      const signedPath = path.join(uploadsDir, signedFileName);
      const existingPdfBytes = fs.readFileSync(originalPath);
      const pdfDoc = await PDFDocument.load(existingPdfBytes);
      const pages = pdfDoc.getPages();
      const lastPage = pages[pages.length - 1];
      const { width } = lastPage.getSize();
      const base64Data = signature.replace(/^data:image\/\w+;base64,/, '');
      const signatureImageBytes = Buffer.from(base64Data, 'base64');
      const signatureImage = await pdfDoc.embedPng(signatureImageBytes);
      const sigWidth = 150;
      const sigHeight = 50;
      lastPage.drawImage(signatureImage, {
        x: width - sigWidth - 50,
        y: 50,
        width: sigWidth,
        height: sigHeight
      });
      const pdfBytes = await pdfDoc.save();
      fs.writeFileSync(signedPath, pdfBytes);
      const updateSql = `UPDATE documents SET signedPath = ?, status = ? WHERE id = ?`;
      db.run(updateSql, [signedFileName, 'signed', documentId], function (error) {
        if (error) return res.status(500).json({ message: 'Error updating document status' });
        res.json({ message: 'Document signed successfully' });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error signing document' });
  }
});

app.get('/api/documents/download/:documentId', authenticateToken, (req, res) => {
  const { documentId } = req.params;
  const sql = `SELECT * FROM documents WHERE id = ? AND userId = ?`;
  db.get(sql, [documentId, req.user.id], (err, doc) => {
    if (err || !doc) return res.status(404).json({ message: 'Document not found' });
    const fileName = doc.signedPath ? doc.signedPath : doc.storagePath;
    const filePath = path.join(uploadsDir, fileName);
    res.download(filePath, fileName, (err) => {
      if (err) res.status(500).json({ message: 'Error downloading file' });
    });
  });
});

app.delete('/api/documents/:documentId', authenticateToken, (req, res) => {
  const { documentId } = req.params;
  const sql = `SELECT * FROM documents WHERE id = ? AND userId = ?`;
  db.get(sql, [documentId, req.user.id], (err, doc) => {
    if (err || !doc) return res.status(404).json({ message: 'Document not found' });
    const fileName = doc.signedPath ? doc.signedPath : doc.storagePath;
    const filePath = path.join(uploadsDir, fileName);
    fs.unlink(filePath, (unlinkErr) => {
      if (unlinkErr) {
        console.error('Error deleting file:', unlinkErr);
      }
      const deleteSql = `DELETE FROM documents WHERE id = ?`;
      db.run(deleteSql, [documentId], (deleteErr) => {
        if (deleteErr) return res.status(500).json({ message: 'Error deleting document from database' });
        res.json({ message: 'Document deleted successfully' });
      });
    });
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
