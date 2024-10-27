import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";  
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import path from 'path';
import multer from 'multer';
import { fileURLToPath } from 'url';

import nodemailer from 'nodemailer';
import crypto from 'crypto';

const JWT_SECRET='waweru';
const  secret_key='waweru'
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
 
    if (schools.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(schools);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
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





  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: 'mikekariuki10028@gmail.com',
      pass: 'qvfk dcie sjop hcxb',
    },
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
      house_id,
    } = req.body;
  
    if (
      !name ||
      !admissionno ||
      !email ||
      !password ||
      !dob ||
      !gender ||
      !department_id ||
      !school_id ||
      !inSchool ||
      (inSchool === 'In-School' && !house_id)
    ) {
      console.log('Validation failed: Missing required fields');
      return res.status(400).json({ message: 'All fields are required' });
    }
  
    try {
  
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
  
      
      const verificationToken = crypto.randomBytes(32).toString('hex');
  
      
    
      const result = await db.query(
        'INSERT INTO users (name, admissionno, email, password, dob, gender, department, school, inSchool, hostel, verificationToken, isVerified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          name,
          admissionno,
          email,
          hashedPassword,
          dob,
          gender,
          department_id,
          school_id,
          inSchool,
          house_id || null,
          verificationToken,
          false, 
        ]
      );
  
      const newUserId = result[0].insertId;
      console.log('New user inserted with ID:', newUserId);
      const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' }); // Token valid for 1 hour

   
    const verificationUrl = `http://localhost:5173/verify?token=${encodeURIComponent(token)}`;
 
      const mailOptions = {
        from: 'mikekariuki10028@gmail.com',
        to: email,
        subject: 'Verify Your Email',
        html: `<p>Thank you for registering! Please verify your email by clicking the link below:</p>
               <a href="${verificationUrl}">Verify Email</a>`,
      };
  
      await transporter.sendMail(mailOptions);
  
      console.log('Verification email sent to:', email);
      return res.status(201).json({ message: 'User registered successfully. Please check your email for verification.' });
    } catch (error) {
      console.error('Error during registration:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  });

  app.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).send('Verification token is missing.');
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(400).send('Invalid or expired verification token.');
    }

    const userEmail = decoded.email;

    try {
      const result = await db.query(
        'UPDATE users SET isVerified = 1 WHERE email = ?',
        [userEmail]
      );

      if (result[0].affectedRows === 0) {
        return res.status(404).send('User not found.');
      }

      res.send('Email successfully verified! You can now log in.');
    } catch (error) {
      console.error('Verification error:', error);
      res.status(500).send('Server error.');
    }
  });
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
      // Fetch user from the database
      const [user] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
      if (user.length === 0) {
          return res.status(401).json({ message: 'Invalid email or password' });
      }

      const existingUser = user[0];
      // Check if user is verified
      if (!existingUser.isVerified) {
          return res.status(403).json({ message: 'Your account is not verified. Please verify your email to log in.' });
      }

      // Compare password
      const passwordMatch = await bcrypt.compare(password, existingUser.password);
      if (!passwordMatch) {
          return res.status(401).json({ message: 'Invalid email or password' });
      }

      // Create JWT token
      const token = jwt.sign({ userId: existingUser.id, email: existingUser.email }, JWT_SECRET, { expiresIn: '1h' });

     
      // Send token back to the client
      return res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
      console.error('Error during login:', error.message);
      return res.status(500).json({ message: 'Server error' });
  }
});


app.post('/logout', (req, res) => {

  res.status(200).json({ message: 'Logout successful' });
});

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.sendStatus(403); // No token provided


  jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
          console.error("Token verification failed:", err.message);
          return res.sendStatus(403); // Invalid token
      }
      req.user = user;
      next(); // Proceed to the next middleware or route handler
  });
};


app.get('/api/user', authenticateToken, async (req, res) => {
    const userId = req.user.userId;

    try {
        const [user] = await db.execute('SELECT name, email FROM users WHERE id = ?', [userId]);

        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const userData = user[0];
        return res.status(200).json({
            name: userData.name,
            email: userData.email,
        });
    } catch (error) {
        console.error('Error fetching user data:', error.message);
        return res.status(500).json({ message: 'Server error' });
    }
});


app.get('/roles', async (req, res) => {
    try {
      const [roles] = await db.execute('SELECT * FROM roles');
      res.json(roles);
    } catch (error) {
      console.error('Error fetching roles:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });
  


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




const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); 
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); 
  }
});

const upload = multer({ storage });


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

  let inSchoolValue = null; 


  if (role === "House Rep") {
    
    inSchoolValue = inSchool === 'In-School' || inSchool === 'Out-School' ? inSchool : null;
  } else {
    
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
  const { schoolId } = req.query;

  // Check if schoolId is provided
  if (!schoolId) {
    return res.status(400).json({ error: 'Missing schoolId parameter' });
  }

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

app.get('/api/candidates/school/:schoolId', async (req, res) => {
  const { schoolId } = req.params;

  try {
    const candidates = await getCandidatesBySchool(schoolId);
    if (candidates.length === 0) {
      return res.status(404).json({ message: "No candidates available for this school." });
    }
    res.json({ candidates });
  } catch (error) {
    console.error('Error fetching candidates by school:', error);
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

app.get('/leaders', async (req, res) => {
  const { school } = req.query; 
  try {
    const leaders = await getLeadersBySchool(school);
    res.json({ leaders });
  } catch (error) {
    console.error('Error fetching leaders:', error);
    res.status(500).json({ error: 'Failed to fetch leaders' });
  }
});





app.post('/vote', async (req, res) => {
  const { email, leaderId, role } = req.body;

  try {
    // Check if the user has already voted
    const existingVote = await db.query('SELECT * FROM votes WHERE voter_email = ? AND candidate_id = ?', [email, leaderId]);
    if (existingVote.length > 0) {
      return res.status(400).json({ success: false, message: 'You have already voted for this candidate.' });
    }

    // Insert the vote
    await db.query('INSERT INTO votes (candidate_id, voter_email, role) VALUES (?, ?, ?)', [leaderId, email, role]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error casting vote:', error);
    res.status(500).json({ success: false, message: 'Error casting vote.' });
  }
});

app.get('/votes/tally', async (req, res) => {
  try {
    const tally = {
      hostelReps: [],
      delegates: [],
      congressPersons: []
    };

    // Tally votes for Hostel Reps
    const hostelReps = await db.query('SELECT candidate_id, COUNT(*) AS votes FROM votes WHERE role = "Hostel Rep" GROUP BY candidate_id');
    tally.hostelReps = hostelReps;

    // Tally votes for Delegates
    const delegates = await db.query('SELECT candidate_id, COUNT(*) AS votes FROM votes WHERE role = "Delegate" GROUP BY candidate_id');
    tally.delegates = delegates;

    // Tally votes for Congress Persons
    const congressPersons = await db.query('SELECT candidate_id, COUNT(*) AS votes FROM votes WHERE role = "Congress Person" GROUP BY candidate_id');
    tally.congressPersons = congressPersons;

    res.json(tally);
  } catch (error) {
    console.error('Error fetching vote tally:', error);
    res.status(500).json({ message: 'Error fetching vote tally.' });
  }
});



app.post('/vote/delegate', async (req, res) => {
  const { leaderId, schoolId } = req.body;

  try {
    // Increment vote count for the candidate in the delegates_votes table
    await db.query(
      'INSERT INTO delegates_votes (leader_id, school_id, vote_count) VALUES (?, ?, 1) ' +
      'ON DUPLICATE KEY UPDATE vote_count = vote_count + 1',
      [leaderId, schoolId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to cast vote for delegate:', err);
    res.status(500).json({ message: 'Failed to cast vote.' });
  }
});

app.post('/vote/congressperson', async (req, res) => {
  const { leaderId, schoolId } = req.body;

  try {
    
    await db.query(
      'INSERT INTO congressperson_votes (leader_id, school_id, vote_count) VALUES (?, ?, 1) ' +
      'ON DUPLICATE KEY UPDATE vote_count = vote_count + 1',
      [leaderId, schoolId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to cast vote for congressperson:', err);
    res.status(500).json({ message: 'Failed to cast vote.' });
  }
});



app.post('/vote/hostelrep', async (req, res) => {
  const { leaderId, schoolId } = req.body;

  try {
    // Increment the vote count for the candidate
    const [result] = await db.query(
      'INSERT INTO hostelrep_votes (leader_id, school_id, vote_count) VALUES (?, ?, 1) ' +
      'ON DUPLICATE KEY UPDATE vote_count = vote_count + 1',
      [leaderId, schoolId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to cast vote for hostel representative:', err);
    res.status(500).json({ message: 'Failed to cast vote.' });
  }
});



app.get('/api/admin/vote-stats', async (req, res) => {
  try {
    const congresspersonVotes = `
      SELECT c.name AS candidateName,c.photo_path AS photo , cv.leader_id, SUM(cv.vote_count) AS voteCount
      FROM congressperson_votes AS cv
      JOIN candidates AS c ON cv.leader_id = c.id  -- Use c.id instead of c.leader_id
      GROUP BY cv.leader_id, c.name
    `;
    
    const delegateVotes = `
      SELECT c.name AS candidateName,c.photo_path AS photo , dv.leader_id, SUM(dv.vote_count) AS voteCount
      FROM delegates_votes AS dv
      JOIN candidates AS c ON dv.leader_id = c.id  -- Use c.id instead of c.leader_id
      GROUP BY dv.leader_id, c.name
    `;
    
    const hostelRepVotes = `
      SELECT c.name AS candidateName,c.photo_path AS photo , hrv.leader_id, SUM(hrv.vote_count) AS voteCount
      FROM hostelrep_votes AS hrv
      JOIN candidates AS c ON hrv.leader_id = c.id  -- Use c.id instead of c.leader_id
      GROUP BY hrv.leader_id, c.name
    `;

    // Execute the queries and get the rows
    const [congressResults] = await db.query(congresspersonVotes);
    const [delegateResults] = await db.query(delegateVotes);
    const [hostelRepResults] = await db.query(hostelRepVotes);

    // Check if results are returned as expected, adjust if necessary
    const voteStats = {
      congressperson: congressResults || [],
      delegate: delegateResults || [],
      hostelRep: hostelRepResults || [],
    };

    res.json(voteStats);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch vote stats' });
  }
});




app.get('/', (req, res) => {
  res.send('Hello, World!');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
