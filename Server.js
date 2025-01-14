import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";  
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import path from 'path';
import multer from 'multer';
import { fileURLToPath } from 'url';
import moment from 'moment';
import cron  from 'node-cron';
import bodyParser from "body-parser";

import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET='waweru';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

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
    // Use environment variables for connection configuration
    db = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
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
})
;
app.get('/api/allhouses', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [houses] = await db.query('SELECT id, house_name FROM houses');
 
    if (houses.length === 0) {
      return res.status(404).json({ message: 'No houses found' });
    }
    
    res.json(houses);
  } catch (error) {
    console.error('Error fetching Houses:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }

});
app.get('/houses', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [houses] = await db.query('SELECT * FROM houses');
 
    if (houses.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(houses);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/congresspersons', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [congresspersons] = await db.query('SELECT * FROM congresspersonroles');
 
    if (congresspersons.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(congresspersons);
  } catch (error) {
    console.error('Error fetching schools:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/campuses', async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Database connection not available' });
    }

    const [campuses] = await db.query('SELECT * FROM campuses');
 
    if (campuses.length === 0) {
      return res.status(404).json({ message: 'No schools found' });
    }
    
    res.json(campuses);
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
      gender,
      department_id,
      school_id,
      residency_status,
      house_id,
      off_campus_address,
      campus,
      internationalStudent,
      disabled,
    } = req.body;
  
    if (
      !name || !admissionno || !email || !password || !gender ||
      !department_id || !school_id || !residency_status || !campus ||
      !internationalStudent || !disabled ||
      (residency_status === 'Resident' && !house_id) ||
      (residency_status === 'Non-Resident' && !off_campus_address)
    ) {
      console.log('Validation failed: Missing required fields');
      return res.status(400).json({ message: 'Validation failed: Missing required fields' });
    }
  
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
  
      const campusValue = campus === 'Yes' ? 1 : 0;
      const intlStudentValue = internationalStudent === 'Yes' ? 1 : 0;
      const disabledValue = disabled === 'Yes' ? 1 : 0;
      const verificationToken = crypto.randomBytes(32).toString('hex');
  
      const result = await db.query(
        'INSERT INTO users (name, admissionno, email, password, gender, department, school, residency_status, hostel, off_campus_address, verificationToken, isVerified, campus, internationalstudent, disabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          name, admissionno, email, hashedPassword, gender, department_id,
          school_id, residency_status, house_id || null, off_campus_address || null,
          verificationToken, false, campusValue, intlStudentValue, disabledValue
        ]
      );
  
      const newUserId = result.insertId;
      console.log('New user inserted with ID:', newUserId);
  
      const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
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
    const token = jwt.sign({ userId: existingUser.id, email: existingUser.email, role: existingUser.role }, JWT_SECRET, { expiresIn: '24h' });

    // Send token and role back to the client
    return res.status(200).json({ message: 'Login successful', token, role: existingUser.role, userId: existingUser.id });
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


app.post('/candidate-register', upload.single('photo'), async (req, res) => {
  const {
    name,
    admissionNo,
    school,
    department,
    role,
    congresspersonType,
    gender,
    motto,
    hostel,
    inSchool,
    year,
    residentStatus,
    disabilityStatus,
    campus
  } = req.body;

  const photoPath = req.file ? req.file.path : null;

  let inSchoolValue = null;

  // Determine in-school value based on role
  if (role === "House Rep") {
    inSchoolValue = inSchool === 'In-School' || inSchool === 'Out-School' ? inSchool : null;
  } else {
    inSchoolValue = null;
  }

  // Dynamically set the schema based on the year
  const schemaName = `evoting_${year}`; // Example: election_2024
  const tableName = 'candidates'; // Table name is the same, but it exists in different schemas (one for each year)

  try {
    // Set the correct database for the query dynamically
    const sql = `
      INSERT INTO ${schemaName}.${tableName} (
        name, admission_no, school_id, department_id, role, congressperson_type, gender, motto, hostel, in_school, photo_path, is_approved, resident_status, disability_status, campus
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Execute the query to insert the candidate's data
    await db.query(sql, [name, admissionNo, school, department, role, congresspersonType, gender, motto, hostel, inSchoolValue, photoPath, false, residentStatus, disabilityStatus, campus]);

    res.status(201).send('Candidate registered successfully');
  } catch (error) {
    console.error('Error inserting candidate:', error);
    res.status(500).send('Error inserting candidate');
  }
});


app.post('/api/approve-candidate/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const sql = 'UPDATE candidates SET is_approved = TRUE WHERE id = ?';
    await db.query(sql, [id]);
    res.status(200).send('Candidate approved successfully');
  } catch (error) {
    console.error('Error approving candidate:', error);
    res.status(500).send('Error approving candidate');
  }
});

app.post('/api/decline-candidate/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const sql = 'DELETE FROM candidates WHERE id = ?';
    await db.query(sql, [id]);
    res.status(200).send('Candidate declined successfully');
  } catch (error) {
    console.error('Error declining candidate:', error);
    res.status(500).send('Error declining candidate');
  }
});
app.get('/api/unapproved-candidates', async (req, res) => {
  try {
    const [unapprovedCandidates] = await db.query(
      'SELECT * FROM candidates WHERE is_approved = FALSE'
    );
    res.status(200).json(unapprovedCandidates);
  } catch (error) {
    console.error('Error fetching unapproved candidates:', error);
    res.status(500).json({ message: 'Server error' });
  }
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


app.get('/api/fetchCandidatesByCampus', async (req, res) => {
  const email = req.query.email;
  const year = new Date().getFullYear();
  const schemaName = `evoting_${year}`;

  console.log('Incoming request for /api/fetchCandidatesByCampus');
  console.log('Email received:', email);

  if (!email) {
    console.log('Error: Email is missing');
    return res.status(400).send('Email is required');
  }

  try {
    // Step 1: Fetch user data
    const userQuery = `
      SELECT internationalstudent, campus, disabled
      FROM users
      WHERE email = ?;
    `;
    const [userData] = await db.execute(userQuery, [email]);

    if (userData.length === 0) {
      console.log('No user found with email:', email);
      return res.status(404).send('User not found');
    }

    console.log('User data fetched:', userData);
    const { campus, disabled } = userData[0];
    console.log('User campus number:', campus);
    console.log('User disability status:', disabled);

    // Step 2: Fetch candidates by campus
    const candidatesQuery = `
      SELECT *
      FROM ${schemaName}.candidates
      WHERE campus = ?;
    `;

    console.log('Querying candidates for campus number:', campus);

    const [candidates] = await db.execute(candidatesQuery, [campus]);

    console.log('Candidates fetched:', candidates);

    if (candidates.length > 0) {
      const response = {
        candidates,
        userDisabilityStatus: disabled
      };
      console.log('Sending candidates and disability status response:', response);
      return res.json(response);
    } else {
      console.log('No candidates found for campus:', campus);
      return res.status(404).send('No candidates found for the specified campus');
    }
  } catch (err) {
    console.error('Error fetching data:', err);
    return res.status(500).send('Error fetching data');
  }
});






const getCandidatesBySchool = async (schoolId, userEmail, year = new Date().getFullYear()) => {
  try {



    // Set the global schema for the users table (assuming 'evoting_global' is the schema)
    const globalSchema = 'evoting_system'; // Replace with your global schema name

    // Dynamically set the schema for candidates based on the year (e.g., evoting_2024)
    const schemaName = `evoting_${year}`;
    
    // Fetch user data (including hostel) from the global schema
    const [user] = await db.execute(`
      SELECT u.hostel
      FROM ${globalSchema}.users u
      WHERE u.email = ?
    `, [userEmail]);

    
    const userHostel = user[0]?.hostel || null;

    if (!userHostel) {
      throw new Error('User does not have a hostel associated');
    }

    // Fetch candidates for the given year and user hostel from the dynamic schema
    const [candidatesByHostel] = await db.execute(`
      SELECT c.id, c.name, c.admission_no, c.role, c.gender, c.motto, c.photo_path
      FROM ${schemaName}.candidates c
      WHERE c.hostel = ? 
    `, [userHostel]);



    // Fetch candidates by school_id and year from the dynamic schema
    const [candidatesBySchool] = await db.execute(`
      SELECT c.id, c.name, c.admission_no, c.role, c.gender, c.motto, c.photo_path
      FROM ${schemaName}.candidates c
      WHERE c.school_id = ? 
    `, [schoolId]);



    // Return both sets of candidates for the given year and schema
    return { 
      candidatesByHostel,
      candidatesBySchool,
      userHostel,
      year
    };
    
  } catch (error) {
    console.error('Error fetching candidates:', error);
    throw error; // Re-throw error to be caught by the route handler
  }
};



app.get('/candidates', async (req, res) => {
  const { schoolId, email } = req.query;

  // Check if schoolId and email are provided
  if (!schoolId || !email) {
    return res.status(400).json({ error: 'Missing schoolId or email parameter' });
  }

  try {
    const { candidatesBySchool, candidatesByHostel } = await getCandidatesBySchool(schoolId, email);

    
    if (candidatesBySchool.length === 0) {
      return res.json({ message: "No candidates available for your school." });
    }

    res.json({ candidatesBySchool, candidatesByHostel });
  } catch (error) {
    console.error('Error fetching candidates:', error);
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});

app.get('/api/candidates', async (req, res) => {
  const { status } = req.query;
  let isApproved;
  if (status === 'approved') {
    isApproved = 1;
  } else if (status === 'declined') {
    isApproved = -1;
  } else {
    isApproved = 0;
  }

  try {
    const [candidates] = await db.query(
      `SELECT c.id, c.name, d.department_name, c.role, c.is_approved
       FROM candidates c
       JOIN departments d ON c.department_id = d.id
       WHERE c.is_approved = ?`, [isApproved]
    );
    res.json(candidates);
  } catch (error) {
    console.error('Error fetching candidates:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/candidates/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [candidate] = await db.query('SELECT * FROM candidates WHERE id = ?', [id]);
    if (candidate.length === 0) {
      return res.status(404).json({ message: 'Candidate not found' });
    }

  
    
    res.json({ candidate: candidate[0]});
  } catch (error) {
    console.error('Error fetching candidate details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/candidates/school/:schoolId', async (req, res) => {
  const { schoolId } = req.params;
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    // Query to fetch candidates by school from the dynamic schema
    const [candidates] = await db.query(
      `
      SELECT id, name,admission_no,role,gender,motto, photo_path AS photo
      FROM ${schemaName}.candidates
      WHERE school_id = ?
      `,
      [schoolId]
    );

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



app.get('/vote-details/:voteId', async (req, res) => {
  const { voteId } = req.params;

  try {
    const [voteDetails] = await db.query(
      'SELECT * FROM votes WHERE vote_id = ?',
      [voteId]
    );

    if (voteDetails.length > 0) {
      // You can return additional information such as leader names, etc.
      res.json(voteDetails[0]);
    } else {
      res.status(404).json({ message: 'Vote details not found' });
    }
  } catch (err) {
    console.error('Error fetching vote details:', err);
    res.status(500).json({ message: 'Failed to fetch vote details' });
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
  const { leaderId, schoolId, year = new Date().getFullYear() } = req.body;

  try {
    // Dynamically set the schema name
    const schemaName = `evoting_${year}`;
    
    // Insert vote into the delegates_votes table in the specified schema
    await db.query(
      `INSERT INTO ${schemaName}.delegates_votes (leader_id, school_id, vote_count) 
       VALUES (?, ?, 1) 
       ON DUPLICATE KEY UPDATE vote_count = vote_count + 1`,
      [leaderId, schoolId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Failed to cast vote for delegate:', err);
    res.status(500).json({ message: 'Failed to cast vote for delegate.' });
  }
});

app.post('/vote/congressperson', async (req, res) => {
  const { leaderId, schoolId, year = new Date().getFullYear() } = req.body;

  try {
    // Dynamically set the schema name
    const schemaName = `evoting_${year}`;
    
    // Insert vote into the congressperson_votes table in the specified schema
    await db.query(
      `INSERT INTO ${schemaName}.congressperson_votes (leader_id, school_id, vote_count) 
       VALUES (?, ?, 1) 
       ON DUPLICATE KEY UPDATE vote_count = vote_count + 1`,
      [leaderId, schoolId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Failed to cast vote for congressperson:', err);
    res.status(500).json({ message: 'Failed to cast vote for congressperson.' });
  }
});

app.post('/vote/hostelrep', async (req, res) => {
  const { leaderId, schoolId, year = new Date().getFullYear() } = req.body;

  try {
    // Dynamically set the schema name
    const schemaName = `evoting_${year}`;
    
    // Insert vote into the hostelrep_votes table in the specified schema
    await db.query(
      `INSERT INTO ${schemaName}.hostelrep_votes (leader_id, school_id, vote_count) 
       VALUES (?, ?, 1) 
       ON DUPLICATE KEY UPDATE vote_count = vote_count + 1`,
      [leaderId, schoolId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Failed to cast vote for hostel representative:', err);
    res.status(500).json({ message: 'Failed to cast vote for hostel representative.' });
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
app.get('/api/admin/vote-stats/:type/:id', async (req, res) => {
  const { type, id } = req.params;
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name

  const voteQueries = {
    school: {
      congressperson: `
        SELECT c.name AS candidateName, c.photo_path AS photo, cv.leader_id, SUM(cv.vote_count) AS voteCount
        FROM ${schemaName}.congressperson_votes AS cv
        JOIN ${schemaName}.candidates AS c ON cv.leader_id = c.id
        WHERE c.school_id = ?
        GROUP BY cv.leader_id, c.name, c.photo_path
      `,
      delegate: `
        SELECT c.name AS candidateName, c.photo_path AS photo, dv.leader_id, SUM(dv.vote_count) AS voteCount
        FROM ${schemaName}.delegates_votes AS dv
        JOIN ${schemaName}.candidates AS c ON dv.leader_id = c.id
        WHERE c.school_id = ?
        GROUP BY dv.leader_id, c.name, c.photo_path
      `,
      hostelRep: `
        SELECT c.name AS candidateName, c.photo_path AS photo, hrv.leader_id, SUM(hrv.vote_count) AS voteCount
        FROM ${schemaName}.hostelrep_votes AS hrv
        JOIN ${schemaName}.candidates AS c ON hrv.leader_id = c.id
        WHERE c.school_id = ?
        GROUP BY hrv.leader_id, c.name, c.photo_path
      `,
    },
    house: {
      candidates: `
        SELECT c.name AS candidateName, c.photo_path AS photo, hrv.leader_id, SUM(hrv.vote_count) AS voteCount
        FROM ${schemaName}.hostelrep_votes AS hrv
        JOIN ${schemaName}.candidates AS c ON hrv.leader_id = c.id
        WHERE c.school_id = ?
        GROUP BY hrv.leader_id, c.name, c.photo_path
      `,
    },
  };

  try {
    const queries = voteQueries[type];
    if (!queries) {
      return res.status(400).json({ error: 'Invalid type specified' });
    }

    const results = await Promise.all(
      Object.entries(queries).map(async ([key, query]) => {
        const [rows] = await db.query(query, [id]);
        return { [key]: rows };
      })
    );

    const data = results.reduce((acc, curr) => ({ ...acc, ...curr }), {});
    res.json(data);
  } catch (err) {
    console.error('Error fetching vote stats:', err);
    res.status(500).json({ error: 'Failed to fetch vote stats' });
  }
});




app.get('/api/candidates/house/:houseId', async (req, res) => {
  const { houseId } = req.params;

  try {
    const candidatesQuery = `
      SELECT c.name AS candidateName, c.photo_path AS photo, dv.leader_id, SUM(dv.vote_count) AS voteCount
      FROM hostelrep_votes AS dv
      JOIN candidates AS c ON dv.leader_id = c.id
      WHERE c.hostel = ?
      GROUP BY dv.leader_id, c.name, c.photo_path
    `;
    
    const [candidatesResults] = await db.query(candidatesQuery, [houseId]);

    res.json({ candidates: candidatesResults });
  } catch (error) {
    console.error('Error fetching candidates for house:', error);
    res.status(500).json({ error: 'Failed to fetch candidates for house' });
  }
});



app.get('/api/elections', async (req, res) => {
  try {
    // Await the query result instead of using a callback
    const [rows] = await db.query('SELECT * FROM elections');
    res.status(200).json(rows); // Send the rows to the client
  } catch (error) {
    console.error('Error fetching elections:', error);  // Log the full error details
    res.status(500).json({ error: 'Failed to fetch elections' });
  }
});


// Example: Create an election
const formatDateForMySQL = (date) => {
  if (!date) {
    throw new Error("Invalid date");
  }
  return new Date(date).toISOString().slice(0, 19).replace("T", " ");
};



app.post('/api/elections', async (req, res) => {
  const { name, start_date, end_date, year } = req.body;

  if (!name || !start_date || !end_date || !year) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Start a transaction
    await db.query('START TRANSACTION');

    // Insert the new election
    const formattedStartDate = new Date(start_date).toISOString().slice(0, 19).replace('T', ' ');
    const formattedEndDate = new Date(end_date).toISOString().slice(0, 19).replace('T', ' ');

    const [result] = await db.query(
      `INSERT INTO elections (name, start_date, end_date, year) VALUES (?, ?, ?, ?)`,
      [name, formattedStartDate, formattedEndDate, year]
    );

    // Call the stored procedure to create the schema and tables
    await db.query(`CALL CreateNewSchemaWithTables2024(?)`, [year]);

    // Commit the transaction
    await db.query('COMMIT');

    res.status(201).json({ message: "Election created successfully", id: result.insertId });
  } catch (error) {
    console.error("Error creating election:", error);

    // Rollback the transaction in case of an error
    await db.query('ROLLBACK');

    res.status(500).json({ error: "Error creating election" });
  }
});




app.get("/api/elections", async (req, res) => {
  const { year } = req.query;

  try {
    const query = year
      ? `SELECT * FROM elections WHERE year = ?`
      : `SELECT * FROM elections`;

    const [rows] = await db.query(query, year ? [year] : []);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching elections:", error);
    res.status(500).json({ error: "Error fetching elections" });
  }
});

// Update election dates
app.put("/api/elections/:id/dates", async (req, res) => {
  const { id } = req.params;
  const { start_date, end_date } = req.body;

  if (!start_date || !end_date) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const formattedStartDate = formatDateForMySQL(start_date);
    const formattedEndDate = formatDateForMySQL(end_date);

    await db.query(
      `UPDATE elections SET start_date = ?, end_date = ? WHERE id = ?`,
      [formattedStartDate, formattedEndDate, id]
    );

    res.json({ message: "Election dates updated" });
  } catch (error) {
    console.error("Error updating election dates:", error);
    res.status(500).json({ error: "Error updating election dates" });
  }
});






















//////////////////////////////////////////////////////////////////////////////////////////


// Update election status
app.put('/api/elections/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // 'open' or 'closed'

  if (!['open', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  try {
    await db.query('UPDATE elections SET status = ? WHERE id = ?', [status, id]);
    res.status(200).json({ message: 'Election status updated successfully' });
  } catch (error) {
    console.error('Error updating election status:', error);
    res.status(500).json({ error: 'Failed to update election status' });
  }
});

// Update election dates
app.put('/api/elections/:id/dates', async (req, res) => {
  const { start_date, end_date } = req.body;
  const electionId = req.params.id;

  // Function to format date to MySQL datetime format
  const formatDateForMySQL = (date) => {
    if (!date) {
      throw new Error('Invalid date');
    }
    return new Date(date).toISOString().slice(0, 19).replace('T', ' ');
  };

  try {
    console.log('Received start_date:', start_date);
    console.log('Received end_date:', end_date);

    const formattedStartDate = formatDateForMySQL(start_date);
    const formattedEndDate = formatDateForMySQL(end_date);

    console.log('Formatted start_date:', formattedStartDate);
    console.log('Formatted end_date:', formattedEndDate);

    await db.query(
      'UPDATE elections SET start_date = ?, end_date = ? WHERE id = ?',
      [formattedStartDate, formattedEndDate, electionId]
    );
    res.status(200).json({ message: 'Dates updated successfully' });
  } catch (error) {
    console.error('Error updating dates:', error);
    res.status(500).json({ error: 'Failed to update dates' });
  }
});



app.get('/api/elections/:id/status', async (req, res) => {
  const { id } = req.params;

  try {
    console.log(`Checking status for election ID: ${id}`);
    const [rows] = await db.query('SELECT end_date FROM elections WHERE id = ?', [id]);
    if (rows.length === 0) {
      console.log(`Election not found for ID: ${id}`);
      return res.status(404).json({ error: 'Election not found' });
    }

    const endDate = new Date(rows[0].end_date);
    const currentDate = new Date();

    console.log(`End date: ${endDate}`);
    console.log(`Current date: ${currentDate}`);

    if (currentDate > endDate) {
      console.log(`Election ID: ${id} is closed`);
      return res.status(200).json({ status: 'closed' });
    } else {
      console.log(`Election ID: ${id} is open`);
      return res.status(200).json({ status: 'open' });
    }
  } catch (error) {
    console.error('Error checking election status:', error);
    res.status(500).json({ error: 'Failed to check election status' });
  }
});

app.post('/admin/register', async (req, res) => {
  const { email, password, name } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query('INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)', [email, hashedPassword, name, 'admin']);
    res.status(201).json({ success: true, id: result.insertId });
  } catch (error) {
    console.error('Error registering admin:', error);
    res.status(500).json({ success: false, error: 'Failed to register admin' });
  }
});

app.post('/vote', async (req, res) => {
  const { email, leaderId, role, schoolId } = req.body;

  try {
    // Check if user already voted for the role
    const existingVote = await db.query(
      'SELECT * FROM votes WHERE email = ? AND role = ?',
      [email, role]
    );

    if (existingVote.length > 0) {
      return res.status(400).json({ success: false, message: 'You have already voted for this role!' });
    }

    // Record the vote
    await db.query(
      'INSERT INTO votes (email, leader_id, role, school_id, created_at) VALUES (?, ?, ?, ?, NOW())',
      [email, leaderId, role, schoolId]
    );

    return res.json({ success: true, message: 'Vote cast successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error processing vote.' });
  }
});

app.get('/voting-status', async (req, res) => {
  const { email } = req.query;

  try {
    const votes = await db.query('SELECT role FROM votes WHERE email = ?', [email]);
    res.json({ success: true, votes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error fetching voting status.' });
  }
});

app.post('/saveVote', async (req, res) => {
  const { email, leaderId, role } = req.body;

  // Validate required parameters
  if (!email || !leaderId || !role) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }

  try {
    // Step 1: Check if the user has already voted for this category
    const [existingVote] = await db.query('SELECT * FROM votes WHERE email = ? AND role = ?', [email, role]);

    if (existingVote.length > 0) {
      // If the user has already voted for this category, reject the new vote
      return res.status(400).json({ message: 'You have already voted for this category.' });
    }

    // Step 2: Insert the new vote into the database
    const query = `
      INSERT INTO votes (email, leader_id, role) 
      VALUES (?, ?, ?)
    `;
    const values = [email, leaderId, role];

    await db.query(query, values);

    // Step 3: Respond with success
    return res.status(200).json({ success: true, message: 'Vote saved successfully' });
  } catch (error) {
    console.error('Error saving vote:', error);
    return res.status(500).json({ message: 'Error saving vote' });
  }
});

///////////////////President///////////////////////////////////////////////////////////////

// Get all leaders
app.get('/leaders', async (req, res) => {
  try {
    const [leaders] = await db.query('SELECT * FROM leaders');
    res.json({ success: true, leaders });
  } catch (error) {
    console.error('Error fetching leaders:', error);
    res.status(500).json({ success: false, message: 'Error fetching leaders' });
  }
});

// Get a specific leader by ID
app.get('/leaders/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [leader] = await db.query('SELECT * FROM leaders WHERE id = ?', [id]);
    if (leader.length === 0) {
      return res.status(404).json({ success: false, message: 'Leader not found' });
    }
    res.json({ success: true, leader: leader[0] });
  } catch (error) {
    console.error('Error fetching leader:', error);
    res.status(500).json({ success: false, message: 'Error fetching leader' });
  }
});

// Create a new leader
app.post('/leaders', async (req, res) => {
  const { partyId, position, name } = req.body;

  // Validate required parameters
  if (!partyId || !position || !name) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }

  try {
    const query = 'INSERT INTO leaders (party_id, position, name) VALUES (?, ?, ?)';
    const values = [partyId, position, name];

    await db.query(query, values);

    res.status(201).json({ success: true, message: 'Leader created successfully' });
  } catch (error) {
    console.error('Error creating leader:', error);
    res.status(500).json({ success: false, message: 'Error creating leader' });
  }
});

// Update a leader
app.put('/leaders/:id', async (req, res) => {
  const { id } = req.params;
  const { partyId, position, name } = req.body;

  // Validate required parameters
  if (!partyId || !position || !name) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }

  try {
    const query = 'UPDATE leaders SET party_id = ?, position = ?, name = ? WHERE id = ?';
    const values = [partyId, position, name, id];

    const [result] = await db.query(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Leader not found' });
    }

    res.json({ success: true, message: 'Leader updated successfully' });
  } catch (error) {
    console.error('Error updating leader:', error);
    res.status(500).json({ success: false, message: 'Error updating leader' });
  }
});

// Delete a leader
app.delete('/leaders/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('DELETE FROM leaders WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Leader not found' });
    }

    res.json({ success: true, message: 'Leader deleted successfully' });
  } catch (error) {
    console.error('Error deleting leader:', error);
    res.status(500).json({ success: false, message: 'Error deleting leader' });
  }
});




app.post('/api/register-president', upload.array('images'), async (req, res) => {
  const { partyName, motto, campaignObjectives, leaders, email, password } = req.body;
  const files = req.files;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user details into the database
    const [userResult] = await db.query(
      'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
      [email, hashedPassword, 'president']
    );

    const presidentId = userResult.insertId;

    // Insert party details into the database
    const [partyResult] = await db.query(
      'INSERT INTO parties (party_name, motto, campaign_objectives, president_id) VALUES (?, ?, ?, ?)',
      [partyName, motto, campaignObjectives, presidentId]
    );

    const partyId = partyResult.insertId;

    // Insert leaders into the database
    for (let i = 0; i < leaders.length; i++) {
      const leader = leaders[i];
      const image = files[i] ? files[i].path : null;
      await db.query(
        'INSERT INTO leaders (party_id, position, name, image) VALUES (?, ?, ?, ?)',
        [partyId, leader.position, leader.name, image]
      );
    }

    res.status(201).json({ success: true, message: 'President registered successfully' });
  } catch (error) {
    console.error('Error registering president:', error);
    res.status(500).json({ success: false, message: 'Failed to register president' });
  }
});



app.get('/api/party', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authorization token is required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const presidentId = decoded.userId;


    const [partyDetails] = await db.query(
      'SELECT * FROM parties WHERE president_id = ?',
      [presidentId]
    );

    if (partyDetails.length === 0) {
      return res.status(404).json({ message: 'Party not found' });
    }

    const [leaders] = await db.query(
      'SELECT * FROM leaders WHERE party_id = ?',
      [partyDetails[0].id]
    );

 

    res.json({ ...partyDetails[0], leaders });
  } catch (error) {
    console.error('Error fetching party details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});
app.get('/candidate-status', async (req, res) => {
  const { email } = req.query;

  try {
    // Fetch the user's admission number based on their email
    const [userDetails] = await db.query(
      'SELECT admissionno FROM users WHERE email = ?',
      [email]
    );

    if (userDetails.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const admissionNo = userDetails[0].admissionno; // Corrected field name
 
    // Check if the admission number exists in the candidates table
    const [candidateDetails] = await db.query(
      'SELECT * FROM candidates WHERE admission_no = ?',
      [admissionNo]
    );
 
    if (candidateDetails.length === 0) {
      return res.json({ isCandidate: false });
    }

    res.json({ isCandidate: true });
  } catch (error) {
    console.error('Error checking candidate status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/candidate/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [candidateDetails] = await db.query(
      'SELECT * FROM candidates WHERE id = ?',
      [id]
    );

    if (candidateDetails.length === 0) {
      return res.status(404).json({ message: 'Candidate not found' });
    }

    const candidate = candidateDetails[0];
    let performanceData = [];
    let otherCandidatesData = [];
    let hasWon = false;

    // Fetch performance data based on the candidate's role
    if (candidate.role === '2') {
      [performanceData] = await db.query(
        'SELECT * FROM hostelrep_votes WHERE leader_id = ?',
        [id]
      );
    } else if (candidate.role === '3') {
      [performanceData] = await db.query(
        'SELECT * FROM delegates_votes WHERE leader_id = ?',
        [id]
      );
      [otherCandidatesData] = await db.query(
        'SELECT c.name, dv.vote_count FROM candidates c JOIN delegates_votes dv ON c.id = dv.leader_id WHERE c.school_id = ? AND c.id != ?',
        [candidate.school_id, id]
      );
    } else if (candidate.role === '1') {
      [performanceData] = await db.query(
        'SELECT * FROM congressperson_votes WHERE leader_id = ?',
        [id]
      );
      [otherCandidatesData] = await db.query(
        'SELECT c.name, cv.vote_count FROM candidates c JOIN congressperson_votes cv ON c.id = cv.leader_id WHERE c.school_id = ? AND c.id != ?',
        [candidate.school_id, id]
      );
    }

    // Determine if the candidate has won in their school
    const totalVotes = performanceData.reduce((acc, data) => acc + data.vote_count, 0);
    const maxVotes = Math.max(...performanceData.map(data => data.vote_count));
    if (totalVotes === maxVotes) {
      hasWon = true;
    }

    res.json({ ...candidate, performanceData, otherCandidatesData, hasWon });
  } catch (error) {
    console.error('Error fetching candidate details:', error);
    res.status(500).json({ message: 'Server error' });
  }4
});
app.get('/api/winners', async (req, res) => {
  try {
    // Fetch the winners for each category grouped by school
    const [houseRepWinners] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, c.hostel, hr.vote_count, c.photo_path
       FROM candidates c
       JOIN hostelrep_votes hr ON c.id = hr.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE hr.vote_count = (
         SELECT MAX(hr2.vote_count)
         FROM hostelrep_votes hr2
         JOIN candidates c2 ON hr2.leader_id = c2.id
         WHERE c2.school_id = c.school_id
       )`
    );

    const [delegateWinners] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, d.vote_count, c.photo_path
       FROM candidates c
       JOIN delegates_votes d ON c.id = d.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE d.vote_count = (
         SELECT MAX(d2.vote_count)
         FROM delegates_votes d2
         JOIN candidates c2 ON d2.leader_id = c2.id
         WHERE c2.school_id = c.school_id
       )`
    );

    const [congresspersonWinners] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, cp.vote_count, c.photo_path
       FROM candidates c
       JOIN congressperson_votes cp ON c.id = cp.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE cp.vote_count = (
         SELECT MAX(cp2.vote_count)
         FROM congressperson_votes cp2
         JOIN candidates c2 ON cp2.leader_id = c2.id
         WHERE c2.school_id = c.school_id
       )`
    );

    res.json({
      houseRepWinners,
      delegateWinners,
      congresspersonWinners,
    });
  } catch (error) {
    console.error('Error fetching winners:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/all/presidential-candidates', async (req, res) => {
  try {
    const [presidentialCandidates] = await db.query(
      `SELECT p.id, p.party_name, p.motto, p.campaign_objectives, l.name AS president_name, s.name AS secretary_name
       FROM parties p
       JOIN leaders l ON p.id = l.party_id AND l.position = 'Secretary'
       LEFT JOIN leaders s ON p.id = s.party_id AND s.position = 'Vice President'`
    );
    res.json(presidentialCandidates);
  } catch (error) {
    console.error('Error fetching presidential candidates:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/vote-president', async (req, res) => {
  const { email, partyId, userId } = req.body;

  if (!email || !partyId) {
    console.error('Error: Missing email or partyId in request body.');
    return res.status(400).json({ message: 'Email and partyId are required.' });
  }

  try {
    console.log(`User attempting to vote: { email: ${email}, partyId: ${partyId} }`);

    // Generate an anonymous ID by hashing the email and partyId with a secret key
    const secretKey = process.env.SECRET_KEY || 'your-secret-key'; // Use an environment variable for the secret key
    const hash = crypto.createHmac('sha256', secretKey)
                       .update(`${email}:${partyId}`)
                       .digest('hex');
    const anonymousId = hash;

    // Check if an anonymous ID already exists in the database
    const [existingVote] = await db.query(
      'SELECT * FROM presidential_votes WHERE anonymous_id = ?',
      [anonymousId]
    );

    console.log('Existing vote:', existingVote);

    if (existingVote.length > 0) {
      console.warn('User has already voted for a president. Rejecting request.');
      return res.status(400).json({ message: 'You have already voted for a president.' });
    }

    // Record the vote with the anonymous ID
    await db.query(
      'INSERT INTO presidential_votes (party_id, anonymous_id, user_id) VALUES (?, ?, ?)', 
      [partyId, anonymousId, userId]
    );
  

    return res.status(200).json({ message: 'Your vote has been recorded successfully.' });
  } catch (error) {
    console.error('Error occurred while processing vote:', error);
    return res.status(500).json({ message: 'An error occurred while processing your vote.' });
  }
});
app.post('/api/admin/lookup-voter', async (req, res) => {
  const { anonymousId } = req.body;

  try {
    const [rows] = await db.query(
      `SELECT u.email, u.name, p.party_id, p.anonymous_id
       FROM presidential_votes p
       JOIN users u ON u.id = p.user_id
       WHERE p.anonymous_id = ?`, [anonymousId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Vote not found or anonymous ID is invalid.' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching voter details.' });
  }
});


app.get('/api/presidential-standings', async (req, res) => {
  const year = req.query.year || new Date().getFullYear(); // Extract year from query or use current year
  const schemaName = `evoting_${year}`; // Dynamic schema name

  try {
    // Query to fetch presidential standings from the dynamic schema
    const [standings] = await db.query(
      `
      SELECT 
        p.id AS party_id, 
        p.party_name, 
        COALESCE(COUNT(v.id), 0) AS votes
      FROM ${schemaName}.parties p
      LEFT JOIN ${schemaName}.presidential_votes v 
        ON p.id = v.party_id
      GROUP BY p.id, p.party_name
      ORDER BY votes DESC
      `
    );

    if (standings.length === 0) {
      return res.status(404).json({ message: `No presidential standings found for the year ${year}.` });
    }

    res.json({ year, standings });
  } catch (error) {
    console.error('Error fetching presidential standings:', error);

    // Check for errors related to missing schema
    if (error.code === 'ER_NO_SUCH_TABLE') {
      return res.status(400).json({
        error: `No data available for the year ${year}. Please check the provided year or ensure the schema exists.`,
      });
    }

    res.status(500).json({ error: 'Failed to fetch presidential standings' });
  }
});


app.get('/api/president/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [candidateDetails] = await db.query(
      `SELECT p.party_name, p.motto, p.campaign_objectives, l.position, l.name, l.image
       FROM parties p
       JOIN leaders l ON p.id = l.party_id
       WHERE p.id = ?`,
      [id]
    );

    if (candidateDetails.length === 0) {
      return res.status(404).json({ message: 'Candidate not found' });
    }

    res.status(200).json(candidateDetails);
  } catch (error) {
    console.error('Error fetching candidate details:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/adminwinners', async (req, res) => {
  try {
    const [winners] = await db.query(
      `SELECT c.id, c.name, c.category, c.votes 
       FROM candidates c 
       WHERE c.is_winner = TRUE`
    );
    res.status(200).json(winners);
  } catch (error) {
    console.error('Error fetching winners:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/////////////////////////////Announcements//////////////////////////////////////////////////////////
app.get('/api/announcements', async (req, res) => {
  try {
    const [announcements] = await db.query('SELECT * FROM announcements ORDER BY scheduled_date DESC');
    res.json(announcements);
  } catch (error) {
    console.error('Error fetching announcements:', error);
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});
app.post('/api/announcements', upload.single('image'), async (req, res) => {
  const { title, content, scheduled_date } = req.body;
  const imagePath = req.file ? req.file.path : null;
  try {
    const formattedDate = new Date(scheduled_date).toISOString().slice(0, 19).replace('T', ' ');
    await db.query('INSERT INTO announcements (title, content, scheduled_date, image_path) VALUES (?, ?, ?, ?)', [title, content, formattedDate, imagePath]);
    res.status(201).json({ message: 'Announcement added successfully' });
  } catch (error) {
    console.error('Error adding announcement:', error);
    res.status(500).json({ error: 'Failed to add announcement' });
  }
});

// Edit an announcement with an image
app.put('/api/announcements/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { title, content, scheduled_date } = req.body;
  const imagePath = req.file ? req.file.path : null;
  try {
    const formattedDate = new Date(scheduled_date).toISOString().slice(0, 19).replace('T', ' ');
    await db.query('UPDATE announcements SET title = ?, content = ?, scheduled_date = ?, image_path = ? WHERE id = ?', [title, content, formattedDate, imagePath, id]);
    res.status(200).json({ message: 'Announcement updated successfully' });
  } catch (error) {
    console.error('Error updating announcement:', error);
    res.status(500).json({ error: 'Failed to update announcement' });
  }
});



/////////////////////////candidate-stats//////////////////////////////////////////////
app.get('/api/candidate-stats', async (req, res) => {
  const { schoolId } = req.query;

  try {
    const [houseRepStats] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, hr.vote_count
       FROM candidates c
       JOIN hostelrep_votes hr ON c.id = hr.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE s.idschools = ?`, [schoolId]
    );

    const [delegateStats] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, d.vote_count
       FROM candidates c
       JOIN delegates_votes d ON c.id = d.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE s.idschools = ?`, [schoolId]
    );

    const [congresspersonStats] = await db.query(
      `SELECT c.name, s.schoolname AS school_name, cp.vote_count
       FROM candidates c
       JOIN congressperson_votes cp ON c.id = cp.leader_id
       JOIN schools s ON c.school_id = s.idschools
       WHERE s.idschools = ?`, [schoolId]
    );

    res.json({
      houseRepStats,
      delegateStats,
      congresspersonStats,
    });
  } catch (error) {
    console.error('Error fetching candidate stats:', error);
    res.status(500).json({ message: 'Server error' });
  }
});




app.get('/api/presidential-winner', async (req, res) => {
  try {
    const [winningParty] = await db.query(`
      SELECT p.id, p.party_name, COUNT(pv.id) AS voteCount
      FROM presidential_votes pv
      JOIN parties p ON pv.party_id = p.id
      GROUP BY p.id
      ORDER BY voteCount DESC
      LIMIT 1
    `);

    if (winningParty.length === 0) {
      return res.status(404).json({ message: 'No winning party found' });
    }

    const [partyLeaders] = await db.query(`
      SELECT l.name, l.position, l.image
      FROM leaders l
      WHERE l.party_id = ?
    `, [winningParty[0].id]);

    res.json({ party: winningParty[0], leaders: partyLeaders });
  } catch (error) {
    console.error('Error fetching presidential winner:', error);
    res.status(500).json({ message: 'Server error' });
  }
});




////////////////////////////////////////School Managament///////////////////////////////////
app.get('/api/schoolsmanagement', async (req, res) => {
  try {
    const query = `
      SELECT sm.school_id, sm.congressperson, sm.delegate, s.schoolname
      FROM schoolsmanagement sm
      JOIN schools s ON sm.school_id = s.idschools
    `;
    
    // Await the query result
    const [results] = await db.query(query);

    // Send the results as JSON
    res.json(results); 
  } catch (err) {
    console.error('Error fetching data:', err);
    res.status(500).json({ message: 'Error fetching data' });
  }
});


// PUT /api/admin/schoolmanagement
app.put('/api/admin/schoolsmanagement', async (req, res) => {
  const updatedSchools = req.body;  // Get updated data from the client
  
  try {
    for (const school of updatedSchools) {
      // First, check if the school exists in the schoolsmanagement table
      const [existingSchool] = await db.execute(
        'SELECT * FROM schoolsmanagement WHERE school_id = ?',
        [school.school_id]
      );

      // If school doesn't exist, insert it; else update it
      if (existingSchool.length === 0) {
        // Insert the new school data with default values for congressperson and delegate
        await db.execute(
          'INSERT INTO schoolsmanagement (school_id, congressperson, delegate) VALUES (?, ?, ?)',
          [school.school_id, school.congressperson || 0, school.delegate || 0]
        );
      } else {
        // Update the existing school data
        await db.execute(
          'UPDATE schoolsmanagement SET congressperson = ?, delegate = ? WHERE school_id = ?',
          [school.congressperson || 0, school.delegate || 0, school.school_id]
        );
      }
    }

    res.status(200).send('Changes saved successfully!');
  } catch (err) {
    console.error('Error updating schools:', err);
    res.status(500).send('Error updating schools');
  }
});



///////////////////////////////////////////////////////
app.get("/campuses", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM campuses");
    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching campuses:", err);
    res.status(500).json({ message: "Error fetching campuses" });
  }
});

// Update campus population and representatives
app.put("/campuses/:id", async (req, res) => {
  const { id } = req.params;
  const { population } = req.body;

  if (typeof population !== "number") {
    return res.status(400).json({ message: "Invalid population value" });
  }

  try {
    // Determine representatives based on population
    let representatives = [];
    if (population < 300) {
      representatives = ["Campus Congressperson"];
    } else if (population <= 500) {
      representatives = ["Male Campus Congressperson", "Female Campus Congressperson"];
    } else {
      representatives = [
        "Campus Representative",
        "Male Campus Congressperson",
        "Female Campus Congressperson",
      ];
    }

    // Update the database
    const [result] = await db.query(
      "UPDATE campuses SET population = ?, representatives = ? WHERE id = ?",
      [population, JSON.stringify(representatives), id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Campus not found" });
    }

    res.status(200).json({ message: "Campus updated successfully", representatives });
  } catch (err) {
    console.error("Error updating campus:", err);
    res.status(500).json({ message: "Error updating campus" });
  }
});




app.get('/', (req, res) => {
  res.send('Hello, World!');
});



app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
