const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect('mongodb://122.166.166.22:27017/Flutter', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
      console.error('MongoDB connection error:', err);
      process.exit(1); // Exit if the connection fails
  });


// User Schema
const userSchema = new mongoose.Schema({
  projectName: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  status: { type: String, default: 'pending' }, // Add status field
  temporaryPassword: { type: String }, // Field to store temporary password
  temporaryPasswordExpires: { type: Date }, // Field to store expiration time
});

// KYC Schema
const kycSchema = new mongoose.Schema({
    personalDetails: {
        employeeId: { type: String, required: true },
        projectName: { type: String, required: true },
        doj: { type: String, required: true },
        designation: { type: String, required: true },
        fullName: { type: String, required: true },
        fatherName: { type: String, required: true },
        motherName: { type: String, required: true },
        dob: { type: String, required: true },
        gender: { type: String, required: true },
        educationalQualification: { type: String, required: true },
        nationality: { type: String, required: true },
        religion: { type: String, required: true },
        phoneNumber: { type: String, required: true },
        bloodGroup: { type: String, required: true },
        languages: { type: [String], required: true },
        maritalStatus: { type: String, required: true },
        experience: { type: String, required: true },
        uanNumber: { type: String, required: true },
        uanStatus: { type: String, required: true },
        esicNumber: { type: String, required: true },
    },
    currentAddress: {
        street: { type: String, required: true },
        city: { type: String, required: true },
        state: { type: String, required: true },
        postalCode: { type: String, required: true },
    },
    permanentAddress: {
        street: { type: String, required: true },
        city: { type: String, required: true },
        state: { type: String, required: true },
        postalCode: { type: String, required: true },
    },
    identificationDetails: {
        identificationType: { type: String, required: true },
        identificationNumber: { type: String, required: true },
    },
    bankDetails: {
        bankName: { type: String, required: true },
        branchName: { type: String, required: true },
        accountNumber: { type: String, required: true },
        ifscCode: { type: String, required: true },
    },
    emergencyContact: {
        name: { type: String, required: true },
        phone: { type: String, required: true },
        relationship: { type: String, required: true },
        aadhar: { type: String, required: true },
    },
}, { timestamps: true });

const suggestionSchema = new mongoose.Schema({
  page: {
    type: String,
    required: true,
  },
  suggestion: {
    type: String,
    required: true,
  },
  status: { type: String, default: 'Pending' }, 
  createdAt: {
    type: Date,
    default: Date.now,
  },
});
const Suggestion = mongoose.model('Suggestion', suggestionSchema);

const otpStore = {};
// Configure your email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'support@exozen.in', // Replace with your email
    pass: 'teth ifvb kyuf ntdi',  // Replace with your email password or app password
  },
});
// Generate a 6-digit OTP
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
// Models
const Kyc = mongoose.model('Kyc', kycSchema);
const User = mongoose.model('User ', userSchema);

// Multer configuration for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });


// Register Endpoint
app.post('/register', async (req, res) => {
  const { projectName, username, password } = req.body;

  try {
    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser   = new User({ projectName, username, password: hashedPassword });

    // Save the user with 'pending' status
    await newUser .save();

    // Generate unique approval link (you can change this to match your actual domain)
    const approveLink = `http://localhost:5000/approve-user?username=${encodeURIComponent(username)}&action=approve`;
    const rejectLink = `http://localhost:5000/reject-user?username=${encodeURIComponent(username)}&action=reject`;

    const mailOptions = {
      from: 'support@exozen.in',
      to: 'support@exozen.in',
      subject: 'New User Registration Approval Needed',
      html: `
       <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: linear-gradient(to bottom, #aed6f1, #abb2b9); border-radius: 10px;">
    <h2 style="color: #FFFFFF; font-weight: bold; text-align: center; margin-bottom: 10px;">New User Registration</h2>
    <p style="color: #FFFFFF; font-size: 16px; margin-bottom: 20px;">A new user has registered:</p>
    <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
        <tr>
            <td style="width: 30%; font-weight: bold; padding: 10px;">Project Name:</td>
            <td style="padding: 10px;">${projectName}</td>
        </tr>
        <tr>
            <td style="width: 30%; font-weight: bold; padding: 10px;">Username:</td>
            <td style="padding: 10px; "color: #FFFFFF;">${username}</td>
        </tr>
    </table>
    <p style="color: #FFFFFF; font-size: 16px; margin-bottom: 20px;">Please approve or reject this registration:</p>
    <div style="text-align: center; margin-bottom: 20px;">
        <a href="${approveLink}" style="display: inline-block; background-color: #4CAF50; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-right: 10px; font-weight: bold;">Approve</a>
        <a href="${rejectLink}" style="display: inline-block; background-color: #DC3545; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reject</a>
    </div>
    <p style="color: #FFFFFF; font-size: 16px; text-align: center; margin-bottom: 20px;">Thank you for your attention!</p>
</div>

      `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending approval email:', error);
        return res.status(500).json({ message: 'User  registered but failed to send approval email', error: error.message });
      }
      res.status(201).json({ message: 'User  registered successfully! Approval needed.' });
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(400).json({ message: 'Error registering user', error: error.message });
  }
});

// Approval Endpoint
app.get('/approve-user', async (req, res) => {
  const { username, action } = req.query; // action can be 'approve' or 'reject'

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User  not found' });
    }

    // Update user status based on action
    if (action === 'approve') {
      user.status = 'Approved';
    } else if (action === 'reject') {
      user.status = 'Rejected';
    } else {
      return res.status(400).json({ message: 'Invalid action' });
    }

    await user.save();

// Optionally, send a notification to the user about the approval/rejection
const mailOptions = {
  from: 'support@exozen.in',
  to: user.username,
  subject: 'Your Registration Status',
  html: `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background-color: #ffffff; border: 1px solid #ddd; border-radius: 10px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);">
      <h2 style="color: #333; text-align: center; margin-bottom: 20px;">Registration Status</h2>
      <p style="color: #555; font-size: 16px;">Greetings from Exozen!</p>
      <p style="color: #555; font-size: 16px;">Your registration has been <strong style="color: ${user.status === 'Approved' ? '#4CAF50' : '#f44336'};">${user.status}</strong>.</p>
      <p style="color: #555; font-size: 16px;">Thank you for your interest in Exozen. ${
        user.status === 'Approved'
          ? 'You can now log in and access your account.'
          : 'Unfortunately, your registration did not meet our criteria at this time.'
      }</p>
      <p style="color: #555; font-size: 16px;">If you have any questions, feel free to <a href="mailto:support@exozen.in" style="color: #4CAF50; text-decoration: underline;">contact us</a>.</p>
      <p style="color: #555; font-size: 16px;">Best regards,<br>The Exozen Team</p>
      <div style="text-align: center; margin-top: 20px;">
        <a href="http://localhost:63105/" style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Log In</a>
      </div>
    </div>
  `,
};

transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.error('Error sending notification email:', error);
    return res.status(500).json({ message: 'Failed to send notification email', error: error.message });
  }
  res.status(200).send(`
    <html>
      <body style="text-align: center; padding-top: 50px;">
        <h2>Status Updated Successfully!</h2>
        <p>The registration has been: <strong>${action}d</strong></p>
        <a href="http://localhost:63105/" style="background-color: #4caf50; color: white; padding: 10px 20px; text-decoration: none;">Go Back to Dashboard</a>
      </body>
    </html>
  `);
});
  } catch (error) {
    console.error('Error approving/rejecting user:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});


// Approval Endpoint
app.get('/reject-user', async (req, res) => {
  const { username, action } = req.query; // action can be 'approve' or 'reject'

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User  not found' });
    }

    // Update user status based on action
    if (action === 'approve') {
      user.status = 'Approved';
    } else if (action === 'reject') {
      user.status = 'Rejected';
    } else {
      return res.status(400).json({ message: 'Invalid action' });
    }

    await user.save();

    const mailOptions = {
      from: 'support@exozen.in',
      to: user.username,
      subject: 'Your Registration Status',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background-color: #ffffff; border: 1px solid #ddd; border-radius: 10px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);">
          <h2 style="color: #333; text-align: center; margin-bottom: 20px;">Registration Status</h2>
          <p style="color: #555; font-size: 16px;">Greetings from Exozen!</p>
          <p style="color: #555; font-size: 16px;">Your registration has been <strong style="color: ${user.status === 'Approved' ? '#4CAF50' : '#f44336'};">${user.status}</strong>.</p>
          <p style="color: #555; font-size: 16px;">Thank you for your interest in Exozen. ${
            user.status === 'Approved'
              ? 'You can now log in and access your account.'
              : 'Unfortunately, your registration did not meet our criteria at this time.'
          }</p>
          <p style="color: #555; font-size: 16px;">If you have any questions, feel free to <a href="mailto:support@exozen.in" style="color: #4CAF50; text-decoration: underline;">contact us</a>.</p>
          <p style="color: #555; font-size: 16px;">Best regards,<br>The Exozen Team</p>
          <div style="text-align: center; margin-top: 20px;">
            <a href="mailto:support@exozen.in" style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Request For Approval</a>
          </div>
        </div>
      `,
    };
    
    

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending notification email:', error);
        return res.status(500).json({ message: 'Failed to send notification email', error: error.message });
      }
      res.status(200).send(`
        <html>
          <body style="text-align: center; padding-top: 50px;">
            <h2>Status Updated Successfully!</h2>
            <p>The registration has been: <strong>${action}d</strong></p>
            <a href="http://localhost:63105/" style="background-color: #4caf50; color: white; padding: 10px 20px; text-decoration: none;">Go Back to Dashboard</a>
          </body>
        </html>
      `);
    });
  } catch (error) {
    console.error('Error approving/rejecting user:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { projectName, username, password } = req.body;

  try {
    // Find the user by project name and username
    const user = await User.findOne({ projectName, username });
    if (!user) {
      return res.status(404 ).json({ message: 'User  not found' });
    }

    // Check the user's approval status
    if (user.status !== 'Approved') {
      return res.status(403).json({ message: 'User  registration is not Approved yet' });
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Successful login
    res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});



// KYC Endpoint
app.post('/kyc', upload.fields([
  { name: 'employeeImage', maxCount: 1 },
  { name: 'frontImage', maxCount: 1 },
  { name: 'backImage', maxCount: 1 },
  { name: 'bankImage', maxCount: 1 },
]), async (req, res) => {
  try {
      const kycData = new Kyc(req.body);
      await kycData.save();
      res.status(201).json({ message: 'KYC details submitted successfully!' });
  } catch (err) {
      console.error('Error submitting KYC:', err);
      res.status(500).json({ message: 'Failed to submit KYC details' });
  }
});


// API endpoint to send OTP for password reset
app.post('/send-otp', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  // Generate OTP and store it with a timestamp (valid for 5 minutes)
  const otp = generateOtp();
  otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 }; // 5 mins expiry

 // Configure the email details
const mailOptions = {
  from: 'your-email@gmail.com', // Your email address
  to: email,
  subject: 'Your OTP for Password Reset',
  html: `
    <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ccc; border-radius: 5px;">
      <h2 style="color: #333;">Password Reset OTP</h2>
      <p style="font-size: 16px; color: #555;">
        Greetings from Exozen..!
      </p>
      <p style="font-size: 16px; color: #555;">
        Your OTP for password reset is: <strong style="color: #007BFF;">${otp}</strong>.
      </p>
      <p style="font-size: 16px; color: #555;">
        Please note that this OTP is valid for <strong>5 minutes</strong>.
      </p>
      <p style="text-align: center; margin-top: 20px;">
        <a href="http://localhost:53939/" style="display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Log In</a>
      </p>
      <p style="font-size: 16px; color: #555;">
        If you did not request a password reset, please ignore this email.
      </p>
      <p style="font-size: 16px; color: #555;">
        Best regards,<br>
        Your Support Team
      </p>
    </div>
  `,
};

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
      res.status(500).json({ message: 'Error sending OTP', error: error.message });
    } else {
      res.status(200).json({ message: 'OTP sent successfully' });
    }
  });
});

// API endpoint to verify OTP (optional, if needed)
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) {
    return res.status(400).json({ message: 'OTP not found or expired' });
  }

  const { otp: storedOtp, expiresAt } = otpStore[email];

  if (Date.now() > expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ message: 'OTP expired' });
  }

  if (otp === storedOtp) {
    delete otpStore[email]; // Clear OTP after successful verification
    res.status(200).json({ message: 'OTP verified successfully' });
  } else {
    res.status(400).json({ message: 'Incorrect OTP' });
  }
});


// API to fetch KYC details by project name
app.get('/kyc/project/:projectName', async (req, res) => {
  const { projectName } = req.params;

  try {
    const kycDetails = await Kyc.find({ "personalDetails.projectName": projectName });
    if (kycDetails.length === 0) {
      return res.status(404).json({ message: 'No KYC details found for this project name' });
    }
    res.status(200).json(kycDetails);
  } catch (error) {
    console.error('Error fetching KYC details by project name:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// API to fetch KYC details by employee ID
app.get('/kyc/employee/:employeeId', async (req, res) => {
  const { employeeId } = req.params;

  try {
    const kycDetails = await Kyc.findOne({ "personalDetails.employeeId": employeeId });
    if (!kycDetails) {
      return res.status(404).json({ message: 'No KYC details found for this employee ID' });
    }
    res.status(200).json(kycDetails);
  } catch (error) {
    console.error('Error fetching KYC details by employee ID:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// API to fetch project-wise KYC count and designation-wise count
app.get('/kyc/projects', async (req, res) => {
  try {
    const result = await Kyc.aggregate([
      {
        $group: {
          _id: {
            projectName: "$personalDetails.projectName",
            designation: "$personalDetails.designation"
          },
          totalKYC: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: "$_id.projectName",
          totalKYC: { $sum: "$totalKYC" },
          designationWiseCount: {
            $push: {
              designation: "$_id.designation",
              count: "$totalKYC"
            }
          }
        }
      },
      {
        $project: {
          projectName: "$_id", // Include projectName
          totalKYC: 1,
          designationWiseCount: 1,
          _id: 0 // Exclude the default _id field
        }
      }
    ]);

    // Format the response according to your specified structure
    const formattedResult = result.map(item => ({
      projectName: item.projectName, // Ensure projectName is included
      totalKYC: item.totalKYC,
      designationWiseCount: item.designationWiseCount,
    }));

    if (formattedResult.length === 0) {
      return res.status(404).json({ message: 'No KYC details found' });
    }

    res.status(200).json(formattedResult);
  } catch (error) {
    console.error('Error fetching project-wise KYC details:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// POST API for submitting suggestions
app.post('/submit-suggestion', async (req, res) => {
  try {
    const { page, suggestion } = req.body;

    // Validate the input
    if (!page || !suggestion) {
      return res.status(400).json({ message: 'Page and suggestion are required.' });
    }

    // Create a new suggestion document
    const newSuggestion = new Suggestion({
      page,
      suggestion,
      status: 'Pending', // Default status
    });

    // Save the suggestion to MongoDB
    await newSuggestion.save();

    // Send the email notification
    sendEmailNotification(newSuggestion);

    res.status(200).json({ message: 'Suggestion submitted successfully.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Function to send an email notification with buttons to update status
async function sendEmailNotification(suggestion) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail', // Using Gmail for sending emails
      auth: {
        user: 'support@exozen.in',
        pass: 'teth ifvb kyuf ntdi', // Use environment variables for security
      },
    });

    const mailOptions = {
      from: 'support@exozen.in',
      to: 'shivanya.dn@exozen.in',
      subject: 'New Suggestion Submitted',
      html: `
        <h3>A new suggestion has been submitted:</h3>
        <p><strong>Page:</strong> ${suggestion.page}</p>
        <p><strong>Suggestion:</strong> ${suggestion.suggestion}</p>
        <p><strong>Status:</strong> ${suggestion.status}</p>

        <p>Please review the suggestion and update the status by clicking one of the following buttons:</p>
        
        <div style="text-align: center;">
          <a href="http://localhost:5000/update-status/${suggestion._id}/YetStart" 
             style="background-color: #f44336; color: white; padding: 10px 20px; margin: 5px; text-decoration: none;">
             Yet Start
          </a>
          <a href="http://localhost:5000/update-status/${suggestion._id}/OnProgress" 
             style="background-color: #ffa500; color: white; padding: 10px 20px; margin: 5px; text-decoration: none;">
             On Progress
          </a>
          <a href="http://localhost:5000/update-status/${suggestion._id}/Completed" 
             style="background-color: #4caf50; color: white; padding: 10px 20px; margin: 5px; text-decoration: none;">
             Completed
          </a>
          <a href="http://localhost:5000/update-status/${suggestion._id}/Failed" 
             style="background-color: #808080; color: white; padding: 10px 20px; margin: 5px; text-decoration: none;">
             Failed
          </a>
        </div>
      `,
    };

    // Send the email
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Error sending email:', error);
  }
}



// New API to update the status of a suggestion
app.get('/update-status/:id/:status', async (req, res) => {
  const { id, status } = req.params;

  try {
    // Validate the input status
    const validStatuses = ['YetStart', 'OnProgress', 'Completed', 'Failed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status.' });
    }

    // Find the suggestion by ID and update the status
    const updatedSuggestion = await Suggestion.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    if (!updatedSuggestion) {
      return res.status(404).json({ message: 'Suggestion not found.' });
    }

    // Send a success response
    res.status(200).send(`
      <html>
        <body style="text-align: center; padding-top: 50px;">
          <h2>Status Updated Successfully!</h2>
          <p>The suggestion status has been updated to: <strong>${status}</strong></p>
          <a href="http://localhost:63105/" style="background-color: #4caf50; color: white; padding: 10px 20px; text-decoration: none;">Go Back to Dashboard</a>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});