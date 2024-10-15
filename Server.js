import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";  
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import path from 'path';
import multer from 'multer';
import { fileURLToPath } from 'url';

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS for all routes
app.use(cors({
    origin: ['http://localhost:5173'], // Allow your React app
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  
    credentials: true, // Allow credentials if needed
}));
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
    console.log('Incoming registration request:', req.body);
  
    const {
      name,
      admissionno,
      email,
      password,
      dob,
      gender,
      department_id,
      school_id,
      inSchool,
      house_id, // Use house_id instead of house name
      
    } = req.body;
  
    // Validate input, make sure house_id is included if inSchool is "In-School"
    if (!name || !admissionno || !email || !password || !dob || !gender || !department_id || !school_id || !inSchool || (inSchool === 'In-School' && !house_id)) {
      console.log('Validation failed: Missing required fields');
      return res.status(400).json({ message: 'All fields are required' });
    }
  
    try {
      // Existing user check and other logic here...
  
      // Insert the new user into the database
      console.log('Inserting new user into the database');
      const result = await db.query(
        'INSERT INTO users (name, admissionno, email, password, dob, gender, department, school, inSchool, hostel) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          name,
          admissionno,
          email,
          password,
          dob,
          gender,
          department_id,
          school_id,
          inSchool,
          house_id || null, // Store NULL if no house is provided
        ]
      );
  
      // Fetch the newly inserted user using the last insert ID
      const newUserId = result[0].insertId;
      console.log('New user inserted with ID:', newUserId);
  
      const [newUser] = await db.query('SELECT * FROM users WHERE id = ?', [newUserId]);
      const { password: _, ...userData } = newUser[0];
  
      console.log('User registered successfully:', userData);
      return res.status(201).json({ message: 'User registered successfully', user: userData });
    } catch (error) {
      console.error('Error during registration:', error);
      return res.status(500).json({ message: 'Server error' });
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
  
        // Compare the provided password with the stored hashed password
        const passwordMatch = await bcrypt.compare(password, existingUser.password);
        if (!passwordMatch) {
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
    inSchool // Expecting this to be either 'In-School', 'Out-School', or null
  } = req.body;
  const photoPath = req.file ? req.file.path : null;

  let inSchoolValue = null; // Initialize inSchoolValue

  // Set inSchoolValue based on the selected role
  if (role === "House Rep") {
    // Make sure inSchool is one of the valid ENUM values or null
    inSchoolValue = inSchool === 'In-School' || inSchool === 'Out-School' ? inSchool : null;
  } else {
    // For other roles, inSchool should be null
    inSchoolValue = null;
  }

  const sql = `
    INSERT INTO candidates (
      name, admission_no, school_id, department_id, role, gender, motto, hostel, in_school, photo_path
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [name, admissionNo, school, department, role, gender, motto, hostel, inSchoolValue, photoPath], (error, results) => {
    if (error) {
      console.error('Error inserting candidate:', error);
      res.status(500).send('Error inserting candidate');
      return;
    }
    res.status(201).send('Candidate registered successfully');
  });
});


// Endpoint to get user profile details
// Add this route to your server file
app.get('/userprofile', async (req, res) => {
  const email = req.query.email; // Get email from query parameter

  try {
    const [user] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    // Check if user exists
    if (user.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const existingUser = user[0];
    
    // Exclude password or any sensitive data from response
    delete existingUser.password; // Optional: do not send the password

    return res.status(200).json({ user: existingUser });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error' });
  }
});
// Assuming you have a database connection established with `db`
// Function to get leaders by school
const getCandidatesBySchool = async (schoolId) => {
  try {
    const [candidates] = await db.execute(`
      SELECT c.id, c.name, c.admission_no, c.role, c.gender, c.motto, c.photo_path
      FROM candidates c
      INNER JOIN schools s ON c.school_id = s.idschools
      WHERE s.idschools = ?
    `, [schoolId]);

    return candidates;
  } catch (error) {
    console.error('Error fetching candidates by school:', error);
    throw error; // Re-throw error to be caught by the route handler
  }
};



app.get('/candidates', async (req, res) => {
  const { schoolId } = req.query; // Use school ID passed in query params
  try {
    const candidates = await getCandidatesBySchool(schoolId);
    
    if (candidates.length === 0) {
      return res.json({ message: "No candidates available for your school." });
    }

    res.json({ candidates });
  } catch (error) {
    console.error('Error fetching candidates:', error);
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});


app.post('/vote', async (req, res) => {
  const { userId, candidateId } = req.body;

  try {
      // Check if the user has already voted
      const [existingVote] = await db.execute('SELECT * FROM votes WHERE user_id = ?', [userId]);
      if (existingVote.length > 0) {
          return res.status(400).json({ message: 'User has already voted' });
      }

      // Insert the new vote
      await db.execute('INSERT INTO votes (user_id, candidate_id) VALUES (?, ?)', [userId, candidateId]);
      return res.status(201).json({ message: 'Vote cast successfully' });
  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Server error' });
  }
});
// Assuming you have express and a database setup
app.get('/leaders', async (req, res) => {
  const { school } = req.query; // Get school from query parameters
  try {
    const leaders = await getLeadersBySchool(school); // Fetch leaders from the database
    res.json({ leaders });
  } catch (error) {
    console.error('Error fetching leaders:', error);
    res.status(500).json({ error: 'Failed to fetch leaders' });
  }
});




app.post('/vote', async (req, res) => {
  const { userId, candidateId } = req.body;

  try {
    // Check if the user has already voted
    const [existingVote] = await db.execute('SELECT * FROM votes WHERE user_id = ?', [userId]);
    if (existingVote.length > 0) {
      return res.status(400).json({ message: 'User has already voted' });
    }

    // Insert the new vote
    await db.execute('INSERT INTO votes (user_id, candidate_id) VALUES (?, ?)', [userId, candidateId]);
    return res.status(201).json({ message: 'Vote cast successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error' });
  }
});



app.get('/', (req, res) => {
  res.send('Hello, World!');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
