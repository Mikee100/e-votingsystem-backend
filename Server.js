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
    const token = jwt.sign({ userId: existingUser.id, email: existingUser.email, role: existingUser.role }, JWT_SECRET, { expiresIn: '24h' });

    // Send token and role back to the client
    return res.status(200).json({ message: 'Login successful', token, role: existingUser.role });
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
      name, admission_no, school_id, department_id, role, gender, motto, hostel, in_school, photo_path, is_approved
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [name, admissionNo, school, department, role, gender, motto, hostel, inSchoolValue, photoPath, false], (error, results) => {
    if (error) {
      console.error('Error inserting candidate:', error);
      res.status(500).send('Error inserting candidate');
      return;
    }
    res.status(201).send('Candidate registered successfully');
  });
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
app.get('/api/admin/vote-stats/school/:schoolId', async (req, res) => {
  const { schoolId } = req.params;

  try {
    const congresspersonVotes = `
      SELECT c.name AS candidateName, c.photo_path AS photo, cv.leader_id, SUM(cv.vote_count) AS voteCount
      FROM congressperson_votes AS cv
      JOIN candidates AS c ON cv.leader_id = c.id
      WHERE c.school_id = ?
      GROUP BY cv.leader_id, c.name, c.photo_path
    `;
    
    const delegateVotes = `
      SELECT c.name AS candidateName, c.photo_path AS photo, dv.leader_id, SUM(dv.vote_count) AS voteCount
      FROM delegates_votes AS dv
      JOIN candidates AS c ON dv.leader_id = c.id
      WHERE c.school_id = ?
      GROUP BY dv.leader_id, c.name, c.photo_path
    `;

    const hostelRepVotes = `
      SELECT c.name AS candidateName, c.photo_path AS photo, hrv.leader_id, SUM(hrv.vote_count) AS voteCount
      FROM hostelrep_votes AS hrv
      JOIN candidates AS c ON hrv.leader_id = c.id
      WHERE c.school_id = ?
      GROUP BY hrv.leader_id, c.name, c.photo_path
    `;

    const [congressResults] = await db.query(congresspersonVotes, [schoolId]);
    const [delegateResults] = await db.query(delegateVotes, [schoolId]);
    const [hostelRepResults] = await db.query(hostelRepVotes, [schoolId]);

    res.json({ congressperson: congressResults, delegate: delegateResults, hostelRep: hostelRepResults });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch vote stats for the school' });
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
app.post('/api/elections', async (req, res) => {
  const { name, start_date, end_date } = req.body;

  if (!name || !start_date || !end_date) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

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

    const [result] = await db.query(
      'INSERT INTO elections (name, start_date, end_date) VALUES (?, ?, ?)',
      [name, formattedStartDate, formattedEndDate]
    );
    res.status(201).json({ message: 'Election created', id: result.insertId });
  } catch (error) {
    console.error('Error creating election:', error); // Log detailed error
    res.status(500).json({ error: 'Error creating election' });
  }
});


app.put('/api/elections/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // 'open' or 'closed'

  if (!['open', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  try {
    await db.query('UPDATE elections SET status = $1 WHERE id = $2', [status, id]);
    res.status(200).json({ message: 'Election status updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update election status' });
  }
});
// Example: Endpoint to update election dates
app.put("/api/elections/:id/dates", async (req, res) => {
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

    const [result] = await db.query(
      "UPDATE elections SET start_date = ?, end_date = ? WHERE id = ?",
      [formattedStartDate, formattedEndDate, electionId]
    );
    res.status(200).json({ message: "Dates updated successfully" });
  } catch (error) {
    console.error("Error updating dates:", error);
    res.status(500).json({ error: "Failed to update dates" });
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
  const { email, partyId } = req.body;

  console.log(`\nReceived POST /api/vote-president request:`, req.body);

  if (!email || !partyId) {
    console.error('Error: Missing email or partyId in request body.');
    return res.status(400).json({ message: 'Email and partyId are required.' });
  }

  try {
    console.log(`User attempting to vote: { email: ${email}, partyId: ${partyId} }`);

    // Check if user has already voted for any party (i.e., only one vote per user allowed)
    const [existingVote] = await db.query(
      'SELECT * FROM presidential_votes WHERE email = ?',
      [email]
    );
    console.log('Existing vote:', existingVote);

    if (existingVote.length > 0) {
      console.warn('User has already voted for a president. Rejecting request.');
      return res.status(400).json({ message: 'You have already voted for a president.' });
    }

    // Record the vote
    const [insertResult] = await db.query(
      'INSERT INTO presidential_votes (email, party_id) VALUES (?, ?)',
      [email, partyId]
    );

    console.log('Vote successfully recorded:', insertResult);

    return res.status(200).json({ message: 'Your vote has been recorded successfully.' });
  } catch (error) {
    console.error('Error occurred while processing vote:', error);
    return res.status(500).json({ message: 'An error occurred while processing your vote.' });
  }
});

app.get('/api/presidential-standings', async (req, res) => {
  try {
    const [standings] = await db.query(
      `SELECT p.id AS party_id, p.party_name, COUNT(v.id) AS votes
       FROM parties p
       LEFT JOIN presidential_votes v ON p.id = v.party_id
       GROUP BY p.id, p.party_name
       ORDER BY votes DESC`
    );
    res.json(standings);
  } catch (error) {
    console.error('Error fetching presidential standings:', error);
    res.status(500).json({ message: 'Server error' });
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


app.get('/', (req, res) => {
  res.send('Hello, World!');
});



app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
