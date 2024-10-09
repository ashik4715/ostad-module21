const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key';
const flash = require('connect-flash');
const session = require('express-session');
const methodOverride = require('method-override');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'uploads')));

// use flash for alert
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: true
}));
app.use(flash());
// Use method override middleware
app.use(methodOverride('_method'));
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://vercel.live"
  );
  next();
});

// MongoDB connection
mongoose.connect('mongodb+srv://ashikurjhalak:jholok7510748209@cluster0.lgpuqkk.mongodb.net/?retryWrites=true&w=majority&appName=AtlasApp')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB', err));

// Student Schema
const StudentSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  profilePicture: String
});

const Student = mongoose.model('Student', StudentSchema);

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// JWT authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, student) => {
      if (err) return res.sendStatus(403);
      req.student = student;
      next();
    });
  } else {
    res.redirect('/login');
  }
};

// Routes
app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

// 1. Student Registration
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if all fields are provided
    if (!name || !email || !password) {
      return res.status(400).send('Please fill in all fields');
    }

    // Check if email already exists
    const existingStudent = await Student.findOne({ email });
    if (existingStudent) {
      return res.status(400).send('Email already registered <br/> <a href="/">Login Now!</a>');
    }

    // Hash the password and save the student
    const hashedPassword = await bcrypt.hash(password, 10);
    const student = new Student({ name, email, password: hashedPassword });
    await student.save();

    res.redirect('/login'); // Redirect to login after successful registration
  } catch (error) {
    console.error('Error registering student:', error); // Log detailed error to console
    res.status(500).send(`Error registering student: ${error.message}`);
  }
});

// 2. Student Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const student = await Student.findOne({ email });
    if (student && await bcrypt.compare(password, student.password)) {
      const token = jwt.sign({ id: student._id }, JWT_SECRET);
      res.cookie('token', token, { httpOnly: true });
      res.redirect('/profile');
    } else {
      res.status(400).send('Invalid credentials');
    }
  } catch (error) {
    res.status(500).send('Error logging in');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// 3. Student auth by JWT token + cookie
// This is handled by the authenticateJWT middleware

// 4. Student profile read
app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    const student = await Student.findById(req.student.id).select('-password');
    if (!student) {
      return res.status(404).send('Student not found');
    }
    res.render('profile', { 
      student, 
      success: req.flash('success'), 
      error: req.flash('error') 
    });
  } catch (error) {
    res.status(500).send('Error fetching profile');
  }
});

// 5. Student profile update
app.put('/profile', authenticateJWT, async (req, res) => {
  try {
    const { name, email } = req.body;
    const student = await Student.findByIdAndUpdate(req.student.id, { name, email }, { new: true });
    
    if (!student) {
      req.flash('error', 'Student not found');
      return res.redirect('/profile');
    }

    req.flash('success', 'Profile updated successfully');
    res.redirect('/profile');
  } catch (error) {
    req.flash('error', 'Error updating profile');
    res.redirect('/profile');
  }
});

// 6. File upload API using multer
app.post('/upload', authenticateJWT, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      req.flash('error', 'No file uploaded');
      return res.redirect('/profile');
    }
    await Student.findByIdAndUpdate(req.student.id, { profilePicture: req.file.filename });
    req.flash('success', 'File uploaded successfully');
    res.redirect('/profile');
  } catch (error) {
    req.flash('error', 'Error uploading file');
    res.redirect('/profile');
  }
});

// 7. File read API
app.get('/file/:filename', authenticateJWT, (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.filename);
  res.sendFile(filePath, (err) => {
      if (err)
      {
        // res.status(404).send('<div class="alert alert-danger" role="alert">File not uploaded!</div>');
      req.flash('error', 'No file uploaded');
      return res.redirect('/profile');
    }
  });
});

// 8. Single file delete API
app.delete('/file/:filename', authenticateJWT, async (req, res) => {
  try {
    const student = await Student.findById(req.student.id);
    if (!student || !student.profilePicture) {
      req.flash('error', 'No profile picture found for deletion');
      return res.redirect('/profile');
    }

    const filePath = path.join(__dirname, 'uploads', student.profilePicture);
    
    fs.unlink(filePath, async (err) => {
      if (err) {
        req.flash('error', 'Error deleting file');
        return res.redirect('/profile');
      }

      // Remove reference to profile picture from the student record
      await Student.findByIdAndUpdate(req.student.id, { $unset: { profilePicture: 1 } });
      
      req.flash('success', 'File deleted successfully');
      res.redirect('/profile');
    });
  } catch (error) {
    req.flash('error', 'Error deleting file');
    res.redirect('/profile');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/login`);
});