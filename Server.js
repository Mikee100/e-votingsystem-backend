import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";  
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import path from 'path';
import multer from 'multer';
const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS for all routes
app.use(cors({
    origin: ['http://localhost:5173'], // Allow your React app
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true, // Allow credentials if needed
}));


app.use(express.json());

// Create MySQL connection
let db;
(async () => {
  try {
    db = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: '10028mike.',
      database: 'evoting_system',
    });

    console.log('Connected to MySQL');
  } catch (error) {
    console.error('Error connecting to MySQL:', error);
  }
})();

// Fetch schools from the database
app.get('/schools', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [schools] = await db.query('SELECT idschools, schoolname FROM schools');
    res.json(schools);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/departments/:schoolId', async (req, res) => {
    const { schoolId } = req.params;
  
    try {
      if (!db) {
        return res.status(500).json({ message: 'Database connection not available' });
      }
  
      const [departments] = await db.query('SELECT iddepartments, department_name FROM departments WHERE school_id = ?', [schoolId]);
      res.json(departments);
    } catch (error) {
      console.error('Error fetching departments:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  app.post('/register', async (req, res) => {
    console.log('Received request:', req.body); // Log the incoming request

    const { name, email, password, gender, termsAndCondition, school, department, admissionno } = req.body;

    // Validate the request body
    if (!name || !email || !password || !gender || typeof termsAndCondition !== 'boolean' || !school || !department || !admissionno) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // Check if the user already exists
        const [results] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Prepare new user data
        const newUser = { 
            name, 
            email, 
            password,  // Use plain password, consider hashing it before storage
            gender, 
            terms_and_condition: termsAndCondition,
            school,
            department,
            admissionno
        };

        // Insert the new user into the database
        await db.query('INSERT INTO users SET ?', newUser);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Unexpected error:', error); // Log error
        res.status(500).json({ message: 'Server error' });
    }
});




app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
      // Fetch the user with the provided email
      const [user] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

      // Check if user exists
      if (user.length === 0) {
          return res.status(401).json({ message: 'Invalid email or password' });
      }

      const existingUser = user[0];

      // Compare the provided password with the stored password (both should be plain text)
      if (existingUser.password !== password) {
          return res.status(401).json({ message: 'Invalid email or password' });
      }

      // Create a JWT token with a secret key
      const token = jwt.sign({ userId: existingUser.id, email: existingUser.email }, 'your_jwt_secret', { expiresIn: '1h' });

      // Send the token back to the client
      return res.status(200).json({ message: 'Login successful', token });

  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Server error' });
  }
});
  

// Fetch roles from the database
app.get('/roles', async (req, res) => {
    try {
      const [roles] = await db.execute('SELECT * FROM roles');
      res.json(roles);
    } catch (error) {
      console.error('Error fetching roles:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });
  


// GET route to fetch houses
app.get('/api/houses', async (req, res) => {
  try {
    const { gender } = req.query;

    // Modify the SQL or database query based on your requirements and database
    // Assuming you have a table named 'houses' with columns 'name' and 'gender'
    let query = 'SELECT * FROM houses';
    const params = [];

    if (gender) {
      query += ' WHERE gender = ?';
      params.push(gender);
    }

    const [houses] = await db.query(query, params);

    res.status(200).json({
      success: true,
      data: houses,
    });
  } catch (error) {
    console.error('Error fetching houses:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch houses',
    });
  }
});

// Set up storage for file uploads using multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Store files in an "uploads" folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Generate unique filename
  }
});

const upload = multer({ storage });

// Handle candidate registration
app.post('/candidate-register', upload.single('photo'), (req, res) => {
  const {
    name,
    admissionNo,
    school,
    department,
    role,
    gender,
    motto,
    hostel,
    inSchool
  } = req.body;
  const photoPath = req.file ? req.file.path : null;

  const sql = `
  INSERT INTO candidates (
    name, admission_no, school_id, department_id, role, gender, motto, hostel, in_school, photo_path
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

db.query(sql, [name, admissionNo, school, department, role, gender, motto, hostel, inSchool, photoPath], (error, results) => {
  if (error) {
    console.error('Error inserting candidate:', error);
    res.status(500).send('Error inserting candidate');
    return;
  }
  res.status(201).send('Candidate registered successfully');
});
});

// Endpoint to get user profile details
app.get('/user-profile', (req, res) => {
  const userId = req.query.userId;

  // Include photo_path in the SELECT statement
  const sql = 'SELECT name, photo_path FROM candidates WHERE id = ?';
  db.query(sql, [userId], (error, results) => {
    if (error) {
      console.error('Error fetching user profile:', error);
      return res.status(500).send('Error fetching user profile');
    }

    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).send('User not found');
    }
  });
});




app.get('/', (req, res) => {
  res.send('Hello, World!');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
