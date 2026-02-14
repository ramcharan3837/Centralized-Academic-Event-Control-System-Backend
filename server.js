const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient, ServerApiVersion, ObjectId, Admin } = require("mongodb");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Razorpay = require('razorpay');
const crypto = require('crypto');
require("dotenv").config();
const sgMail = require('@sendgrid/mail');

if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log('✅ SendGrid API configured successfully');
} else {
  console.error('❌ WARNING: SENDGRID_API_KEY not found in environment variables!');
  console.error('   Emails will NOT work. Please add SENDGRID_API_KEY to Render environment.');
}

// ========================================
// EMAIL CONFIGURATION
// ========================================
const nodemailer = require('nodemailer');
const cron = require('node-cron');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Verify transporter configuration
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email configuration error:', error.message);
    console.error('Please check EMAIL_USER and EMAIL_PASSWORD in .env file');
  } else {
    console.log('✅ Email server is ready to send messages');
  }
});


const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());


const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;


// MongoDB connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});


// 4. Initialize Razorpay instance (add after MongoDB client initialization)


// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res
      .status(401)
      .json({ status: "Error", message: "Access token required" });
  }


  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ status: "Error", message: "Invalid or expired token" });
    }
    req.user = user; // { email, role, userId }
    next();
  });
};
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Middleware to check if user is admin or organizer
const isAdminOrOrganizer = (req, res, next) => {
  if (req.user.role !== "admin" && req.user.role !== "organizer") {
    return res.status(403).json({
      status: "Error",
      message: "Admin or organizer access required",
    });
  }
  next();
};


// Initialize database and predefined accounts
async function initializeDatabase() {
  try {
    await client.connect();
    const db = client.db("project_event_db");


    const usersCollection = db.collection("users");
    const eventsCollection = db.collection("events");
    const registrationsCollection = db.collection("registrations");
    const attendanceCollection = db.collection("attendance");
    const notificationsCollection = db.collection("notifications");
    // inside initializeDatabase, after other collections
    const venuesCollection = db.collection("venues");
    await venuesCollection.createIndex({ name: 1 }, { unique: true });
// Add this to initializeDatabase function
const otpCollection = db.collection("password_reset_otps");
await otpCollection.createIndex({ email: 1 });
await otpCollection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 600 }); // OTP expires after 10 minutes



    await usersCollection.createIndex({ email: 1 }, { unique: true });
    setupAutomatedReminders()


    const predefinedAccounts = [
      {
        fullName: "Admin User",
        rollNumber: "ADMIN001",
        branch: "MCA",
        role: "admin",
        email: "admin@college.com",
        password: await bcrypt.hash("admin123", 10),
        approved: true,
      },
      {
        fullName: "Event Organizer",
        rollNumber: "ORG001",
        branch: "CSE",
        role: "organizer",
        email: "organizer@college.com",
        password: "organizer123",
        approved: true,
      },
      {
        fullName: "Event Organizer",
        rollNumber: "ORG001",
        branch: "CSE",
        role: "organizer",
        email: "organizer@college.co",
        password: "organizer123",
        approved: true,
      },

    ];


    for (const account of predefinedAccounts) {
      const exists = await usersCollection.findOne({ email: account.email });
      if (!exists) {
        await usersCollection.insertOne({
          ...account,
          createdAt: new Date(),
        });
        console.log(`✅ Created ${account.role} account: ${account.email}`);
      }
    }


    await registrationsCollection.createIndex(
      { userId: 1, eventId: 1 },
      { unique: true }
    );


    await attendanceCollection.createIndex(
      { userId: 1, eventId: 1 },
      { unique: true }
    );


    await notificationsCollection.createIndex({ userId: 1, isRead: 1 });


    console.log("✅ Database initialization complete");
  } catch (err) {
    console.error("❌ Database initialization error:", err);
  }
}


// --------------------- NOTIFICATION HELPER ---------------------


async function createNotification({ userId, eventId, type, title, message }) {
  const db = client.db("project_event_db");
  const notificationsCollection = db.collection("notifications");


  const doc = {
    userId: new ObjectId(userId),
    eventId: eventId ? new ObjectId(eventId) : null,
    type, // e.g. "event_created", "event_updated"
    title,
    message,
    isRead: false,
    createdAt: new Date(),
  };


  await notificationsCollection.insertOne(doc);
}


// --------------------- USER & ORGANIZER ---------------------

const otpStore = new Map(); // Format: { email: { otp, expiresAt, userData } }

// Helper function to generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Helper function to validate strong password
const validatePassword = (password) => {
  // Minimum 8 characters, at least one uppercase, one lowercase, one number, one special character
  const minLength = password.length >= 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  return {
    isValid: minLength && hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar,
    errors: {
      minLength,
      hasUpperCase,
      hasLowerCase,
      hasNumber,
      hasSpecialChar
    }
  };
};

// Helper function to send OTP email
const sendOTPEmail = async (email, otp, fullName) => {
  // Check if API key exists
  if (!process.env.SENDGRID_API_KEY) {
    console.error('❌ SENDGRID_API_KEY not configured');
    throw new Error('Email service not configured. Please contact administrator.');
  }

  // Check if sender email exists
  if (!process.env.EMAIL_USER) {
    console.error('❌ EMAIL_USER not configured');
    throw new Error('Email sender not configured. Please contact administrator.');
  }

  console.log(`📧 Sending OTP email to: ${email}`);
  console.log(`📧 From: ${process.env.EMAIL_USER}`);
  console.log(`📧 OTP: ${otp}`);

  const msg = {
    to: email,
    from: process.env.EMAIL_USER, // Must be your verified sender in SendGrid
    subject: 'Email Verification - Event Management System',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
          <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #2563eb; margin: 0;">Email Verification</h1>
          </div>
          
          <p style="color: #333; font-size: 16px; line-height: 1.6;">
            Hello <strong>${fullName}</strong>,
          </p>
          
          <p style="color: #333; font-size: 16px; line-height: 1.6;">
            Thank you for registering with our Event Management System! To complete your registration, please use the following One-Time Password (OTP):
          </p>
          
          <div style="background-color: #f0f7ff; border-left: 4px solid #2563eb; padding: 20px; margin: 30px 0; text-align: center;">
            <p style="margin: 0; color: #666; font-size: 14px; margin-bottom: 10px;">Your OTP Code</p>
            <h2 style="margin: 0; color: #2563eb; font-size: 36px; letter-spacing: 8px; font-family: 'Courier New', monospace;">
              ${otp}
            </h2>
          </div>
          
          <p style="color: #666; font-size: 14px; line-height: 1.6;">
            ⏰ This OTP will expire in <strong>10 minutes</strong>.
          </p>
          
          <p style="color: #666; font-size: 14px; line-height: 1.6;">
            If you didn't request this registration, please ignore this email.
          </p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
          
          <p style="color: #999; font-size: 12px; text-align: center;">
            Event Management System<br>
            This is an automated email, please do not reply.
          </p>
        </div>
      </div>
    `,
  };

  try {
    const response = await sgMail.send(msg);
    console.log('✅ Email sent successfully via SendGrid!');
    console.log('📧 Response Status:', response[0].statusCode);
    console.log('📧 Message ID:', response[0].headers['x-message-id']);
    return response;
  } catch (error) {
    console.error('❌ SendGrid email error!');
    console.error('Error Message:', error.message);
    
    if (error.response) {
      console.error('Status Code:', error.response.statusCode);
      console.error('Response Body:', JSON.stringify(error.response.body, null, 2));
      
      // Handle specific SendGrid errors
      if (error.response.body.errors) {
        error.response.body.errors.forEach(err => {
          console.error('  - Error:', err.message);
          console.error('    Field:', err.field);
          console.error('    Help:', err.help);
        });
      }
    }
    
    // Throw user-friendly error
    throw new Error('Failed to send verification email. Please try again or contact support.');
  }
};
// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { fullName, rollNumber, branch, role, email, password, otp, step } = req.body;

    // ================================================
    // STEP 1: Request OTP (Initial Registration)
    // ================================================
    if (step === 'request-otp') {
      // Validate required fields
      if (!fullName || !rollNumber || !branch || !role || !email || !password) {
        return res.status(400).json({ 
          status: "Error", 
          message: "All fields are required" 
        });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ 
          status: "Error", 
          message: "Invalid email format" 
        });
      }

      // Validate strong password
      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        let errorMessage = "Password must contain: ";
        const errors = [];
        if (!passwordValidation.errors.minLength) errors.push("at least 8 characters");
        if (!passwordValidation.errors.hasUpperCase) errors.push("one uppercase letter");
        if (!passwordValidation.errors.hasLowerCase) errors.push("one lowercase letter");
        if (!passwordValidation.errors.hasNumber) errors.push("one number");
        if (!passwordValidation.errors.hasSpecialChar) errors.push("one special character (!@#$%^&*)");
        
        return res.status(400).json({ 
          status: "Error", 
          message: errorMessage + errors.join(", "),
          passwordRequirements: passwordValidation.errors
        });
      }

      const db = client.db("project_event_db");
      const usersCollection = db.collection("users");

      // Check if email already exists
      const existingUser = await usersCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ 
          status: "Error", 
          message: "Email already exists" 
        });
      }

      // Generate OTP
      const generatedOTP = generateOTP();
      const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

      // Store OTP and user data temporarily
      otpStore.set(email, {
        otp: generatedOTP,
        expiresAt,
        userData: {
          fullName,
          rollNumber,
          branch,
          role,
          email,
          password,
        }
      });

      // Send OTP email
      try {
        await sendOTPEmail(email, generatedOTP, fullName);
      } catch (emailError) {
        console.error("Error sending email:", emailError);
        otpStore.delete(email);
        return res.status(500).json({ 
          status: "Error", 
          message: "Failed to send verification email. Please check your email address and try again." 
        });
      }

      // Clean up expired OTPs
      for (const [key, value] of otpStore.entries()) {
        if (value.expiresAt < Date.now()) {
          otpStore.delete(key);
        }
      }

      return res.status(200).json({
        status: "Success",
        message: "OTP sent to your email. Please verify within 10 minutes.",
        requireOTP: true,
        email: email
      });
    }

    // ================================================
    // STEP 2: Verify OTP and Complete Registration
    // ================================================
    if (step === 'verify-otp') {
      if (!email || !otp) {
        return res.status(400).json({ 
          status: "Error", 
          message: "Email and OTP are required" 
        });
      }

      // Check if OTP exists for this email
      const otpData = otpStore.get(email);
      if (!otpData) {
        return res.status(400).json({ 
          status: "Error", 
          message: "OTP not found or expired. Please request a new OTP." 
        });
      }

      // Check if OTP is expired
      if (otpData.expiresAt < Date.now()) {
        otpStore.delete(email);
        return res.status(400).json({ 
          status: "Error", 
          message: "OTP has expired. Please request a new OTP." 
        });
      }

      // Verify OTP
      if (otpData.otp !== otp.trim()) {
        return res.status(400).json({ 
          status: "Error", 
          message: "Invalid OTP. Please check and try again." 
        });
      }

      // OTP is valid, proceed with registration
      const db = client.db("project_event_db");
      const usersCollection = db.collection("users");

      const { userData } = otpData;

      // Double-check if email exists
      const existingUser = await usersCollection.findOne({ email: userData.email });
      if (existingUser) {
        otpStore.delete(email);
        return res.status(400).json({ 
          status: "Error", 
          message: "Email already exists" 
        });
      }

      // Determine approval status
      let approved = userData.role === "user";

      // Create new user
      const newUser = {
        fullName: userData.fullName,
        rollNumber: userData.rollNumber,
        branch: userData.branch,
        role: userData.role,
        email: userData.email,
        password: userData.password,
        approved,
        emailVerified: true,
        createdAt: new Date(),
      };

      await usersCollection.insertOne(newUser);

      // Delete OTP from store
      otpStore.delete(email);

      return res.status(200).json({
        status: "Success",
        message: `Registration successful! ${userData.role === 'organizer' ? 'Please wait for admin approval before logging in.' : 'You can now login with your credentials.'}`,
        emailVerified: true
      });
    }

    // ================================================
    // STEP 3: Resend OTP
    // ================================================
    if (step === 'resend-otp') {
      if (!email) {
        return res.status(400).json({ 
          status: "Error", 
          message: "Email is required" 
        });
      }

      // Check if OTP exists for this email
      const otpData = otpStore.get(email);
      if (!otpData) {
        return res.status(400).json({ 
          status: "Error", 
          message: "No pending registration found. Please start registration again." 
        });
      }

      // Generate new OTP
      const newOTP = generateOTP();
      const expiresAt = Date.now() + 10 * 60 * 1000;

      // Update OTP data
      otpData.otp = newOTP;
      otpData.expiresAt = expiresAt;
      otpStore.set(email, otpData);

      // Send new OTP email
      try {
        await sendOTPEmail(email, newOTP, otpData.userData.fullName);
      } catch (emailError) {
        console.error("Error sending email:", emailError);
        return res.status(500).json({ 
          status: "Error", 
          message: "Failed to send verification email. Please try again." 
        });
      }

      return res.status(200).json({
        status: "Success",
        message: "New OTP sent to your email.",
        email: email
      });
    }

    // If none of the above conditions match
    return res.status(400).json({
      status: "Error",
      message: "Invalid request. Please specify the step (request-otp, verify-otp, or resend-otp)."
    });

  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ 
      status: "Error", 
      message: "Registration failed. Please try again." 
    });
  }
});
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, value] of otpStore.entries()) {
    if (value.expiresAt < now) {
      otpStore.delete(key);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`✅ OTP cleanup: Removed ${cleaned} expired OTP(s). Active: ${otpStore.size}`);
  }
}, 15 * 60 * 1000);


// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password || !role)
      return res
        .status(400)
        .json({ status: "Error", message: "All fields are required" });


    const db = client.db("project_event_db");
    const usersCollection = db.collection("users");


    const user = await usersCollection.findOne({ email });
    if (!user)
      return res
        .status(400)
        .json({ status: "Error", message: "User not found" });


    if (user.role !== role)
      return res
        .status(400)
        .json({ status: "Error", message: "Role mismatch" });


    if (role === "organizer" && !user.approved)
      return res.status(403).json({
        status: "Error",
        message: "Organizer not approved yet",
      });


    if (user.password !== password)
      return res
        .status(400)
        .json({ status: "Error", message: "Incorrect password" });


    const token = jwt.sign(
      { email: user.email, role: user.role, userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );


    res.status(200).json({
      status: "Success",
      message: "Login successful",
      token,
      user: {
        email: user.email,
        role: user.role,
        fullName: user.fullName,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "Error", message: "Server error" });
  }
});


// Get all users (admin + organizer)
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const usersCollection = db.collection("users");


    const users = await usersCollection
      .find({})
      .project({
        fullName: 1,
        email: 1,
        role: 1,
        branch: 1,
        rollNumber: 1,
        approved: 1,
        createdAt: 1,
      })
      .toArray();


    res.json({ status: "Success", users });
  } catch (err) {
    console.error("Failed to fetch users", err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to fetch users" });
  }
});


// Update user role (admin + organizer)
app.put(
  "/users/:id/role",
  authenticateToken,
 
  async (req, res) => {
    try {
      const userId = req.params.id;
      const { role } = req.body;


      if (!role || !["user", "organizer", "admin"].includes(role)) {
        return res
          .status(400)
          .json({ status: "Error", message: "Invalid role" });
      }


      const db = client.db("project_event_db");
      const usersCollection = db.collection("users");


      let approved = true;
      if (role === "organizer") approved = false;


      const result = await usersCollection.updateOne(
        { _id: new ObjectId(userId) },
        { $set: { role, approved } }
      );


      if (result.matchedCount === 0) {
        return res
          .status(404)
          .json({ status: "Error", message: "User not found" });
      }


      res.json({ status: "Success", message: "User role updated" });
    } catch (err) {
      console.error("Failed to update user role", err);
      res
        .status(500)
        .json({ status: "Error", message: "Failed to update user role" });
    }
  }
);


// --------------------- EVENTS ---------------------


// Create event (requires authentication)
app.post("/events", authenticateToken, async (req, res) => {
  try {
    const { name, date, venue, strength, shortDesc, about, learning, registrationFee
} =
      req.body;
console.log("Request Body:", req.body);

    if (
      !name ||
      !date ||
      !venue ||
      !strength ||
      !shortDesc ||
      !about ||
      !learning
      

    ) {
      return res
        .status(400)
        .json({ status: "Error", message: "All fields are required" });
    }


    const db = client.db("project_event_db");
    const usersCollection = db.collection("users");
    const eventsCollection = db.collection("events");


    const user = await usersCollection.findOne({ email: req.user.email });


    const isPrivileged = user.role === "admin" || user?.role === "organizer";
    const approved = isPrivileged ? true : false;


    const newEvent = {
      name,
      date,
      venue,
      strength: parseInt(strength),
      shortDesc,
      about,
      learning,
registrationFee: parseInt(registrationFee),
      createdBy: {
        email: user.email,
        fullName: user.fullName,
        role: user.role,
      },
      approved,
      createdAt: new Date(),
      

    };


    const result = await eventsCollection.insertOne(newEvent);


    const successMessage = isPrivileged
      ? "Event created and published successfully"
      : "Event submitted for approval";


    // If normal user created the event, notify admins & organizers


    const userRole = user.role === "admin" || user?.role === "organizer" || user?.role === "user";
    if (userRole) {
      const approvers = await usersCollection
        .find({ role: { $in: ["admin", "organizer", "user"] } })
        .project({ _id: 1 })
        .toArray();


      const notifyPromises = approvers.map((u) =>
        createNotification({
          userId: u._id,
          eventId: result.insertedId,
          type: "event_created",
          title: "New event created",
          message: `${user.fullName} created a new event "${name}" `,
        })
      );
      await Promise.all(notifyPromises);
    }


    res.status(201).json({
      status: "Success",
      message: successMessage,
      insertedId: result.insertedId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "Error", message: "Server error" });
  }
});


// Get all approved events (public) with registration count
app.get("/events", async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const registrationsCollection = db.collection("registrations");


    const events = await eventsCollection
      .aggregate([
        { $match: { approved: true } },
        {
          $lookup: {
            from: "registrations",
            localField: "_id",
            foreignField: "eventId",
            as: "regs",
          },
        },
        {
          $addFields: {
            currentRegistrations: { $size: "$regs" },
          },
        },
        {
          $project: {
            regs: 0,
          },
        },
      ])
      .toArray();


    res.json({ events });
  } catch (err) {
    console.error("Failed to fetch events", err);
    res.status(500).json({ message: "Failed to fetch events" });
  }
});


// Get pending events (admin + organizer)
app.get(
  "/events/pending",
  authenticateToken,
  async (req, res) => {
    try {
      const events = await client
        .db("project_event_db")
        .collection("events")
        .find({ approved: false })
        .toArray();


      res.json({ events });
    } catch (err) {
      res.status(500).json({ message: "Failed to fetch pending events" });
    }
  }
);


// Approve event (admin + organizer)
app.put(
  "/events/:id/approve",
  authenticateToken,
  async (req, res) => {
    try {
      const id = req.params.id;
      const db = client.db("project_event_db");
      const eventsCollection = db.collection("events");


      const result = await eventsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            approved: true,
            approvedBy: req.user.email,
            approvedAt: new Date(),
          },
        }
      );


      if (result.matchedCount === 0) {
        return res.status(404).json({ message: "Event not found" });
      }


      res.json({ message: "Event approved successfully" });
    } catch (err) {
      res.status(500).json({ message: "Failed to approve event" });
    }
  }
);


// Reject event (admin + organizer)
app.delete(
  "/events/:id/reject",
  authenticateToken,
  async (req, res) => {
    try {
      const id = req.params.id;
      await client
        .db("project_event_db")
        .collection("events")
        .deleteOne({ _id: new ObjectId(id) });


      res.json({ message: "Event rejected and deleted successfully" });
    } catch (err) {
      res.status(500).json({ message: "Failed to reject event" });
    }
  }
);


// Delete event
app.delete("/events/:id", authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    await client
      .db("project_event_db")
      .collection("events")
      .deleteOne({ _id: new ObjectId(id) });


    res.json({ message: "Event deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete event" });
  }
});


// Update event
app.put('/events/:id', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const updatedData = req.body;
    
    const db = client.db('project_event_db');
    const eventsCollection = db.collection('events');
    const usersCollection = db.collection('users');
    
    const user = await usersCollection.findOne({ email: req.user.email });
    const oldEvent = await eventsCollection.findOne({ _id: new ObjectId(eventId) });
    
    if (!oldEvent) return res.status(404).json({ message: 'Event not found' });
    
    // Organizer can ONLY update OWN events
    const isOwner = oldEvent.createdBy === req.user.email;
    // if (req.user.role !== 'admin' && !isOwner) {
    //   return res.status(403).json({ message: 'Can only update your own events' });
    // }
    
    // Organizers: reset approval (needs admin re-approval)
    if (req.user.role === 'organizer') {
      updatedData.approved = false;
    }
    
    updatedData.updatedAt = new Date();
    const result = await eventsCollection.updateOne(
      { _id: new ObjectId(eventId) }, 
      { $set: updatedData }
    );
    
    if (result.matchedCount === 0) return res.status(404).json({ message: 'Event not found' });
    
    const newEvent = await eventsCollection.findOne({ _id: new ObjectId(eventId) });
    res.json({ message: 'Event updated successfully', event: newEvent });
    
  } catch (err) {
    console.error('Update event error:', err);
    res.status(500).json({ error: err.message });
  }
});



// --------------------- REGISTRATIONS ---------------------


// Register for an event (user-specific)
app.post("/events/:id/register", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const userId = req.user.userId;


    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const usersCollection = db.collection("users");
    const registrationsCollection = db.collection("registrations");


    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
      approved: true,
    });
    if (!event) {
      return res.status(404).json({
        status: "Error",
        message: "Event not found or not approved",
      });
    }


    const user = await usersCollection.findOne({
      _id: new ObjectId(userId),
    });
    if (!user) {
      return res
        .status(404)
        .json({ status: "Error", message: "User not found" });
    }


    const existing = await registrationsCollection.findOne({
      userId: new ObjectId(userId),
      eventId: new ObjectId(eventId),
    });
    if (existing) {
      return res.status(400).json({
        status: "Error",
        message: "Already registered for this event",
      });
    }


    const registration = {
      userId: new ObjectId(userId),
      eventId: new ObjectId(eventId),
      registeredAt: new Date(),
    };


    await registrationsCollection.insertOne(registration);


    res.status(201).json({
      status: "Success",
      message: "Registered for event successfully",
    });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to register for event" });
  }
});


// Get all events registered by a specific user
app.get(
  "/users/:userId/registrations",
  authenticateToken,
  async (req, res) => {
    try {
      const requestedUserId = req.params.userId;
      const authUserId = req.user.userId;


      if (req.user.role !== "admin" && authUserId !== requestedUserId) {
        return res.status(403).json({
          status: "Error",
          message: "Not authorized to view these registrations",
        });
      }


      const db = client.db("project_event_db");
      const registrationsCollection = db.collection("registrations");
      const eventsCollection = db.collection("events");


      const regs = await registrationsCollection
        .find({ userId: new ObjectId(requestedUserId) })
        .toArray();


      const eventIds = regs.map((r) => r.eventId);
      if (eventIds.length === 0) {
        return res.json({ status: "Success", events: [] });
      }


      const events = await eventsCollection
        .find({ _id: { $in: eventIds } })
        .toArray();


      res.json({ status: "Success", events });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        status: "Error",
        message: "Failed to fetch registered events",
      });
    }
  }
);


// Get all users registered for a specific event (admin + organizer)
app.get(
  "/events/:eventId/registrations",
  authenticateToken,

  async (req, res) => {
    try {
      const { eventId } = req.params;
      const db = client.db("project_event_db");


      const registrationsCollection = db.collection("registrations");
      const usersCollection = db.collection("users");
      const attendanceCollection = db.collection("attendance");


      const regs = await registrationsCollection
        .find({ eventId: new ObjectId(eventId) })
        .toArray();


      if (regs.length === 0) {
        return res.json({
          status: "Success",
          registrations: [],
        });
      }


      const userIds = regs.map((r) => r.userId);


      const users = await usersCollection
        .find({ _id: { $in: userIds } })
        .project({
          fullName: 1,
          email: 1,
          branch: 1,
          rollNumber: 1,
        })
        .toArray();


      const attendanceDocs = await attendanceCollection
        .find({ eventId: new ObjectId(eventId) })
        .toArray();


      const attendanceMap = {};
      attendanceDocs.forEach((a) => {
        attendanceMap[a.userId.toString()] = a.status; // "present" | "absent"
      });


      const result = regs.map((reg) => {
        const u = users.find(
          (usr) => usr._id.toString() === reg.userId.toString()
        );
        return {
          userId: reg.userId,
          fullName: u?.fullName || "Unknown",
          email: u?.email || "",
          branch: u?.branch || "",
          rollNumber: u?.rollNumber || "",
          registeredAt: reg.registeredAt,
          attendanceStatus:
            attendanceMap[reg.userId.toString()] || "not_marked",
        };
      });


      res.json({
        status: "Success",
        registrations: result,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        status: "Error",
        message: "Failed to fetch registrations for this event",
      });
    }
  }
);


// Mark attendance for a user in an event (admin + organizer)
app.post(
  "/events/:eventId/attendance",
  authenticateToken,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const { userId, status } = req.body; // "present" | "absent"


      if (!userId || !["present", "absent"].includes(status)) {
        return res.status(400).json({
          status: "Error",
          message: "userId and valid status (present/absent) are required",
        });
      }


      const db = client.db("project_event_db");
      const attendanceCollection = db.collection("attendance");


      await attendanceCollection.updateOne(
        {
          eventId: new ObjectId(eventId),
          userId: new ObjectId(userId),
        },
        {
          $set: {
            status,
            markedAt: new Date(),
          },
        },
        { upsert: true }
      );


      res.json({
        status: "Success",
        message: "Attendance updated",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        status: "Error",
        message: "Failed to update attendance",
      });
    }
  }
);


// --------------------- FEEDBACKS ---------------------


// Add feedback for an event
app.post("/events/:id/feedback", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const userId = req.user.userId;
    const { feedback } = req.body;


    if (!feedback || !feedback.trim()) {
      return res
        .status(400)
        .json({ status: "Error", message: "Feedback is required" });
    }


    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const usersCollection = db.collection("users");
    const feedbacksCollection = db.collection("feedbacks");


    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
    });
    if (!event) {
      return res
        .status(404)
        .json({ status: "Error", message: "Event not found" });
    }


    const user = await usersCollection.findOne({
      _id: new ObjectId(userId),
    });
    if (!user) {
      return res
        .status(404)
        .json({ status: "Error", message: "User not found" });
    }


    const doc = {
      eventId: new ObjectId(eventId),
      userId: new ObjectId(userId),
      userName: user.fullName,
      feedback: feedback.trim(),
      createdAt: new Date(),
    };


    await feedbacksCollection.insertOne(doc);


    res
      .status(201)
      .json({ status: "Success", message: "Feedback submitted" });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to submit feedback" });
  }
});


// Get all feedbacks for an event
app.get("/events/:id/feedback", async (req, res) => {
  try {
    const eventId = req.params.id;
    const db = client.db("project_event_db");
    const feedbacksCollection = db.collection("feedbacks");


    const feedbacks = await feedbacksCollection
      .find({ eventId: new ObjectId(eventId) })
      .sort({ createdAt: -1 })
      .toArray();


    res.json({ status: "Success", feedbacks });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to fetch feedback" });
  }
});


// --------------------- NOTIFICATIONS ---------------------


// Get all notifications for logged-in user
app.get("/notifications", authenticateToken, async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const notificationsCollection = db.collection("notifications");


    const notifications = await notificationsCollection
      .find({ userId: new ObjectId(req.user.userId) })
      .sort({ createdAt: -1 })
      .toArray();


    res.json({ status: "Success", notifications });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to fetch notifications" });
  }
});


// Mark a single notification as read
app.put("/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const notificationsCollection = db.collection("notifications");


    await notificationsCollection.updateOne(
      {
        _id: new ObjectId(req.params.id),
        userId: new ObjectId(req.user.userId),
      },
      { $set: { isRead: true } }
    );


    res.json({ status: "Success" });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to update notification" });
  }
});


// Mark all notifications as read
app.put("/notifications/read-all", authenticateToken, async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const notificationsCollection = db.collection("notifications");


    await notificationsCollection.updateMany(
      { userId: new ObjectId(req.user.userId), isRead: false },
      { $set: { isRead: true } }
    );


    res.json({ status: "Success" });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to update notifications" });
  }
});



// Get all attended events for a specific user (events in the past)
// Get all attended events for a specific user (events where user was marked present)
app.get("/users/:userId/attended", authenticateToken, async (req, res) => {
  try {
    const requestedUserId = req.params.userId;
    const authUserId = req.user.userId; // from JWT

    // Only allow user to view their own attended events or admin sees all
    if (req.user.role !== "admin" && authUserId !== requestedUserId) {
      return res
        .status(403)
        .json({ status: "Error", message: "Not authorized to view these events" });
    }

    const db = client.db("project_event_db");
    const attendanceCollection = db.collection("attendance");
    const eventsCollection = db.collection("events");

    // Find attendance records for this user where status is "present"
    const attendanceRecords = await attendanceCollection
      .find({ 
        userId: new ObjectId(requestedUserId),
        status: "present"
      })
      .toArray();

    if (attendanceRecords.length === 0) {
      return res.json({ status: "Success", events: [] });
    }

    // Extract event IDs from attendance records
    const eventIds = attendanceRecords.map((record) => record.eventId);

    // Fetch event details
    const attendedEvents = await eventsCollection
      .find({ _id: { $in: eventIds } })
      .toArray();

    return res.json({ status: "Success", events: attendedEvents });
  } catch (err) {
    console.error(err);
    return res
      .status(500)
      .json({ status: "Error", message: "Failed to fetch attended events" });
  }
});






// --------------------- VENUES ---------------------
// Get all venues (public)
app.get("/venues", async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const venuesCollection = db.collection("venues");
    const venues = await venuesCollection
      .find({})
      .sort({ name: 1 })
      .toArray();
    res.json({ status: "Success", venues });
  } catch (err) {
    console.error("Failed to fetch venues", err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to fetch venues" });
  }
});


// Create venue (admin only)
app.post("/venues", authenticateToken, async (req, res) => {
  try {
    const { name, location, capacity, notes } = req.body;
    if (!name || !name.trim()) {
      return res
        .status(400)
        .json({ status: "Error", message: "Venue name is required" });
    }


    const db = client.db("project_event_db");
    const venuesCollection = db.collection("venues");


    const existing = await venuesCollection.findOne({
      name: name.trim(),
    });
    if (existing) {
      return res.status(400).json({
        status: "Error",
        message: "Venue with this name already exists",
      });
    }


    const doc = {
      name: name.trim(),
      location: location?.trim() || "",
      capacity: capacity ? parseInt(capacity) : null,
      notes: notes?.trim() || "",
      createdBy: req.user.email,
      createdAt: new Date(),
    };


    await venuesCollection.insertOne(doc);
    res.status(201).json({
      status: "Success",
      message: "Venue created successfully",
    });
  } catch (err) {
    console.error("Failed to create venue", err);
    res
      .status(500)
      .json({ status: "Error", message: "Failed to create venue" });
  }
});




// Default route
app.get("/", (req, res) => res.send("Server is running successfully ✅"));


// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await initializeDatabase();
});

// ============================================
// RAZORPAY INTEGRATION - ADD TO YOUR EXISTING SERVER
// ============================================

// 1. Install razorpay package
// npm install razorpay

// 2. Add to your .env file:
/*
RAZORPAY_KEY_ID=rzp_test_your_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
*/

// 3. Add this at the top of your server file with other requires


// ============================================
// 5. ADD THESE ROUTES TO YOUR SERVER FILE
// ============================================

// --------------------- PAYMENT ROUTES ---------------------

// Create Razorpay Order
app.post("/payment/create-order", authenticateToken, async (req, res) => {
  try {
    const { amount, eventId } = req.body;
    const userId = req.user.userId;

    // Validate input
    if (!amount || !eventId) {
      return res.status(400).json({
        status: "Error",
        message: "Amount and eventId are required",
      });
    }

    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");

    // Check if event exists
    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
      approved: true,
    });

    if (!event) {
      return res.status(404).json({
        status: "Error",
        message: "Event not found or not approved",
      });
    }

    // Create Razorpay order
    const options = {
      amount: amount * 100, // amount in paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
      notes: {
        eventId,
        userId,
        eventName: event.name,
      },
    };

    const order = await razorpay.orders.create(options);

    res.status(200).json({
      status: "Success",
      order,
      key: process.env.RAZORPAY_KEY_ID,
    });
  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({
      status: "Error",
      message: "Failed to create order",
      error: error.message,
    });
  }
});

// Verify Payment and Register User
app.post("/payment/verify-payment", authenticateToken, async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      eventId,
      amount,
    } = req.body;

    const userId = req.user.userId;

    // Validate input
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        status: "Error",
        message: "Missing payment details",
      });
    }

    // Verify signature
    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    if (razorpay_signature !== expectedSign) {
      return res.status(400).json({
        status: "Error",
        message: "Invalid payment signature",
      });
    }

    // Payment verified successfully
    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const usersCollection = db.collection("users");
    const registrationsCollection = db.collection("registrations");
    const paymentsCollection = db.collection("payments");

    // Check if event exists
    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
      approved: true,
    });

    if (!event) {
      return res.status(404).json({
        status: "Error",
        message: "Event not found or not approved",
      });
    }

    // Check if user exists
    const user = await usersCollection.findOne({
      _id: new ObjectId(userId),
    });

    if (!user) {
      return res.status(404).json({
        status: "Error",
        message: "User not found",
      });
    }

    // Check for duplicate registration
    const existing = await registrationsCollection.findOne({
      userId: new ObjectId(userId),
      eventId: new ObjectId(eventId),
    });

    if (existing) {
      return res.status(400).json({
        status: "Error",
        message: "Already registered for this event",
      });
    }

    // Save payment details
    const paymentDoc = {
      userId: new ObjectId(userId),
      eventId: new ObjectId(eventId),
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      amount: amount,
      currency: "INR",
      status: "completed",
      createdAt: new Date(),
    };

    await paymentsCollection.insertOne(paymentDoc);

    // Register user for event
    const registration = {
      userId: new ObjectId(userId),
      eventId: new ObjectId(eventId),
      paymentId: razorpay_payment_id,
      orderId: razorpay_order_id,
      paymentStatus: "completed",
      amount: amount,
      registeredAt: new Date(),
    };

    const result = await registrationsCollection.insertOne(registration);

    // Send notification to user
    await createNotification({
      userId: userId,
      eventId: eventId,
      type: "registration_success",
      title: "Registration Successful",
      message: `You have successfully registered for "${event.name}". Payment ID: ${razorpay_payment_id}`,
    });

    res.status(200).json({
      status: "Success",
      message: "Payment verified and registered successfully",
      paymentId: razorpay_payment_id,
      orderId: razorpay_order_id,
      registration: result.insertedId,
    });
  } catch (error) {
    console.error("Error verifying payment:", error);
    res.status(500).json({
      status: "Error",
      message: "Payment verification failed",
      error: error.message,
    });
  }
});

// Get Payment Details (Optional)
app.get("/payment/:paymentId", authenticateToken, async (req, res) => {
  try {
    const { paymentId } = req.params;

    const payment = await razorpay.payments.fetch(paymentId);

    res.status(200).json({
      status: "Success",
      payment,
    });
  } catch (error) {
    console.error("Error fetching payment:", error);
    res.status(500).json({
      status: "Error",
      message: "Failed to fetch payment details",
      error: error.message,
    });
  }
});

// Get User's Payment History
app.get("/users/:userId/payments", authenticateToken, async (req, res) => {
  try {
    const requestedUserId = req.params.userId;
    const authUserId = req.user.userId;

    // Only allow user to view their own payments or admin sees all
    if (req.user.role !== "admin" && authUserId !== requestedUserId) {
      return res.status(403).json({
        status: "Error",
        message: "Not authorized to view these payments",
      });
    }

    const db = client.db("project_event_db");
    const paymentsCollection = db.collection("payments");

    const payments = await paymentsCollection
      .aggregate([
        { $match: { userId: new ObjectId(requestedUserId) } },
        {
          $lookup: {
            from: "events",
            localField: "eventId",
            foreignField: "_id",
            as: "eventDetails",
          },
        },
        {
          $unwind: {
            path: "$eventDetails",
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $project: {
            razorpay_payment_id: 1,
            razorpay_order_id: 1,
            amount: 1,
            currency: 1,
            status: 1,
            createdAt: 1,
            eventName: "$eventDetails.name",
            eventDate: "$eventDetails.date",
          },
        },
        { $sort: { createdAt: -1 } },
      ])
      .toArray();

    res.json({
      status: "Success",
      payments,
    });
  } catch (error) {
    console.error("Error fetching payments:", error);
    res.status(500).json({
      status: "Error",
      message: "Failed to fetch payment history",
      error: error.message,
    });
  }
});

// Get All Payments for an Event (Admin/Organizer only)
app.get(
  "/events/:eventId/payments",
  authenticateToken,
  async (req, res) => {
    try {
      const { eventId } = req.params;
      const db = client.db("project_event_db");
      const paymentsCollection = db.collection("payments");

      const payments = await paymentsCollection
        .aggregate([
          { $match: { eventId: new ObjectId(eventId) } },
          {
            $lookup: {
              from: "users",
              localField: "userId",
              foreignField: "_id",
              as: "userDetails",
            },
          },
          {
            $unwind: {
              path: "$userDetails",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              razorpay_payment_id: 1,
              razorpay_order_id: 1,
              amount: 1,
              currency: 1,
              status: 1,
              createdAt: 1,
              userName: "$userDetails.fullName",
              userEmail: "$userDetails.email",
              rollNumber: "$userDetails.rollNumber",
            },
          },
          { $sort: { createdAt: -1 } },
        ])
        .toArray();

      // Calculate total revenue
      const totalRevenue = payments.reduce(
        (sum, payment) => sum + (payment.amount || 0),
        0
      );

      res.json({
        status: "Success",
        payments,
        totalPayments: payments.length,
        totalRevenue,
      });
    } catch (error) {
      console.error("Error fetching event payments:", error);
      res.status(500).json({
        status: "Error",
        message: "Failed to fetch event payments",
        error: error.message,
      });
    }
  }
);

// ============================================
// 6. MODIFY YOUR EXISTING REGISTRATION ENDPOINT
// Comment out or remove the old /events/:id/register endpoint
// and replace with this one that checks for free events
// ============================================

// Register for Free Events (No Payment Required)
app.post("/events/:id/register-free", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const userId = req.user.userId;

    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const usersCollection = db.collection("users");
    const registrationsCollection = db.collection("registrations");

    const event = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
      approved: true,
    });

    if (!event) {
      return res.status(404).json({
        status: "Error",
        message: "Event not found or not approved",
      });
    }

    // Check if event has registration fee
    if (event.registrationFee && event.registrationFee > 0) {
      return res.status(400).json({
        status: "Error",
        message: "This event requires payment. Please use the payment flow.",
      });
    }

    const user = await usersCollection.findOne({
      _id: new ObjectId(userId),
    });

    if (!user) {
      return res.status(404).json({
        status: "Error",
        message: "User not found",
      });
    }

    const existing = await registrationsCollection.findOne({
      userId: new ObjectId(userId),
      eventId: new ObjectId(eventId),
    });

    if (existing) {
      return res.status(400).json({
        status: "Error",
        message: "Already registered for this event",
      });
    }

    const registration = {
      userId: new ObjectId(userId),
      eventId: new ObjectId(eventId),
      paymentStatus: "free",
      registeredAt: new Date(),
    };

    await registrationsCollection.insertOne(registration);

    res.status(201).json({
      status: "Success",
      message: "Registered for event successfully",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      status: "Error",
      message: "Failed to register for event",
    });
  }
});

// ============================================
// 7. UPDATE YOUR EVENTS SCHEMA
// Add registrationFee field when creating events
// Modify your /events POST endpoint to include registrationFee
// ============================================

/*
Example: In your create event endpoint, add registrationFee:

const newEvent = {
  name,
  date,
  venue,
  strength: parseInt(strength),
  shortDesc,
  about,
  learning,
  registrationFee: parseInt(registrationFee) || 0, // ADD THIS LINE
  createdBy: {
    email: user.email,
    fullName: user.fullName,
    role: user.role,
  },
  approved,
  createdAt: new Date(),
};
*/

// ========================================
// NEW ROUTES TO ADD TO YOUR server.js
// Add these at the end of your server.js file (before app.listen)
// ========================================

// First, add these requires at the top of your server.js:
// const nodemailer = require('nodemailer');
// const cron = require('node-cron');
// const createCsvWriter = require('csv-writer').createObjectCsvWriter;
// const multer = require('multer');
// const fs = require('fs');
// const path = require('path');


// ========================================
// EMAIL ROUTES
// ========================================

// Send email to registered users for a specific event
app.post('/send-email-registered/:eventId', authenticateToken, async (req, res) => {
  try {
    const { eventId } = req.params;
    const { subject, message } = req.body;

    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const registrationsCollection = db.collection("registrations");
    const usersCollection = db.collection("users");

    const event = await eventsCollection.findOne({ _id: new ObjectId(eventId) });
    if (!event) {
      return res.status(404).json({ status: 'Error', message: 'Event not found' });
    }

    const registrations = await registrationsCollection.find({ 
      eventId: new ObjectId(eventId) 
    }).toArray();

    if (registrations.length === 0) {
      return res.status(404).json({ status: 'Error', message: 'No registered users found' });
    }

    const userIds = registrations.map(r => r.userId);
    const users = await usersCollection.find({ 
      _id: { $in: userIds } 
    }).toArray();

    const emailPromises = users.map(user => {
      const mailOptions = {
        from: process.env.SENDGRID_FROM_EMAIL|| process.env.EMAIL_USER,
        to: user.email,
        subject: subject || `Reminder: ${event.name}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #2563eb;">Event Reminder</h2>
            <p>Dear ${user.fullName},</p>
            <p>${message || 'This is a reminder about your registered event.'}</p>
            <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <h3 style="color: #1f2937; margin-top: 0;">Event Details:</h3>
              <ul style="list-style: none; padding: 0;">
                <li><strong>Event:</strong> ${event.name}</li>
                <li><strong>Date:</strong> ${event.date}</li>
                <li><strong>Venue:</strong> ${event.venue}</li>
                <li><strong>Description:</strong> ${event.shortDesc || ''}</li>
              </ul>
            </div>
            <p>We look forward to seeing you!</p>
            <p style="color: #6b7280;">Best regards,<br>Event Management Team</p>
          </div>
        `
      };
      return sgMail.send(mailOptions);
    });

    await Promise.all(emailPromises);

    res.json({ 
      status: 'Success', 
      message: `Email sent to ${users.length} registered users` 
    });

  } catch (error) {
    console.error('Error sending emails:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to send emails' });
  }
});

// Send email to all users in database
app.post('/send-email-all', authenticateToken, isAdminOrOrganizer, async (req, res) => {
  try {
    const { subject, message, eventId } = req.body;

    const db = client.db("project_event_db");
    const usersCollection = db.collection("users");
    const eventsCollection = db.collection("events");

    const users = await usersCollection.find({}).toArray();
    
    if (users.length === 0) {
      return res.status(404).json({ status: 'Error', message: 'No users found' });
    }

    let eventDetails = '';
    if (eventId) {
      const event = await eventsCollection.findOne({ _id: new ObjectId(eventId) });
      if (event) {
        eventDetails = `
          <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="color: #1f2937; margin-top: 0;">Event Details:</h3>
            <ul style="list-style: none; padding: 0;">
              <li><strong>Event:</strong> ${event.name}</li>
              <li><strong>Date:</strong> ${event.date}</li>
              <li><strong>Venue:</strong> ${event.venue}</li>
              <li><strong>Description:</strong> ${event.shortDesc || ''}</li>
            </ul>
          </div>
        `;
      }
    }

    const emailPromises = users.map(user => {
      const mailOptions = {
        from: process.env.SENDGRID_FROM_EMAIL|| process.env.EMAIL_USER,
        to: user.email,
        subject: subject || 'Event Announcement',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #2563eb;">Event Announcement</h2>
            <p>Dear ${user.fullName},</p>
            <p>${message || 'We have an exciting event coming up!'}</p>
            ${eventDetails}
            <p style="color: #6b7280;">Best regards,<br>Event Management Team</p>
          </div>
        `
      };
      return sgMail.send(mailOptions);
    });

    await Promise.all(emailPromises);

    res.json({ 
      status: 'Success', 
      message: `Email sent to ${users.length} users` 
    });

  } catch (error) {
    console.error('Error sending emails:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to send emails' });
  }
});

// ========================================
// AUTOMATED REMINDER SCHEDULER
// ========================================
function setupAutomatedReminders() {
  cron.schedule('0 * * * *', async () => {
    try {
      const now = new Date();
      const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
      const dayAfterTomorrow = new Date(now.getTime() + 25 * 60 * 60 * 1000);

      const db = client.db("project_event_db");
      const eventsCollection = db.collection("events");
      const registrationsCollection = db.collection("registrations");
      const usersCollection = db.collection("users");

      const upcomingEvents = await eventsCollection.find({
        date: {
          $gte: tomorrow.toISOString().split('T')[0],
          $lt: dayAfterTomorrow.toISOString().split('T')[0]
        },
        reminderSent: { $ne: true }
      }).toArray();

      for (const event of upcomingEvents) {
        const registrations = await registrationsCollection.find({ 
          eventId: event._id 
        }).toArray();

        if (registrations.length > 0) {
          const userIds = registrations.map(r => r.userId);
          const users = await usersCollection.find({ 
            _id: { $in: userIds } 
          }).toArray();

          const emailPromises = users.map(user => {
            const mailOptions = {
              from: process.env.SENDGRID_FROM_EMAIL || process.env.EMAIL_USER,
              to: user.email,
              subject: `Reminder: ${event.name} - Tomorrow!`,
              html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                  <h2 style="color: #2563eb;">Event Reminder - Tomorrow!</h2>
                  <p>Dear ${user.fullName},</p>
                  <p>This is a friendly reminder that you're registered for the following event happening <strong>tomorrow</strong>:</p>
                  <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #1f2937; margin-top: 0;">Event Details:</h3>
                    <ul style="list-style: none; padding: 0;">
                      <li><strong>Event:</strong> ${event.name}</li>
                      <li><strong>Date:</strong> ${event.date}</li>
                      <li><strong>Venue:</strong> ${event.venue}</li>
                      <li><strong>Description:</strong> ${event.shortDesc || ''}</li>
                    </ul>
                  </div>
                  <p>Please make sure to arrive on time. We look forward to seeing you!</p>
                  <p style="color: #6b7280;">Best regards,<br>Event Management Team</p>
                </div>
              `
            };
            return sgMail.send(mailOptions);
          });

          await Promise.all(emailPromises);

          await eventsCollection.updateOne(
            { _id: event._id },
            { $set: { reminderSent: true } }
          );

          console.log(`Automated reminder sent for event: ${event.name} to ${users.length} users`);
        }
      }

    } catch (error) {
      console.error('Error in automated reminder:', error);
    }
  });

  console.log('✅ Automated reminder scheduler started - checking every hour');
}

// ========================================
// CSV DOWNLOAD ROUTES
// ========================================
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const fs = require('fs');
const path = require('path');

// Download all users as CSV
app.get('/download-users-csv', authenticateToken, isAdminOrOrganizer, async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const usersCollection = db.collection("users");

    const users = await usersCollection.find({}).toArray();

    if (users.length === 0) {
      return res.status(404).json({ status: 'Error', message: 'No users found' });
    }

    const csvFilePath = path.join(__dirname, `all-users-${Date.now()}.csv`);

    const csvWriter = createCsvWriter({
      path: csvFilePath,
      header: [
        { id: 'id', title: 'User ID' },
        { id: 'fullName', title: 'Full Name' },
        { id: 'email', title: 'Email' },
        { id: 'rollNumber', title: 'Roll Number' },
        { id: 'branch', title: 'Branch' },
        { id: 'role', title: 'Role' },
        { id: 'approved', title: 'Approved' },
        { id: 'createdAt', title: 'Created At' }
      ]
    });

    const userData = users.map(user => ({
      id: user._id.toString(),
      fullName: user.fullName || '',
      email: user.email || '',
      rollNumber: user.rollNumber || '',
      branch: user.branch || '',
      role: user.role || '',
      approved: user.approved ? 'Yes' : 'No',
      createdAt: user.createdAt ? new Date(user.createdAt).toLocaleDateString() : ''
    }));

    await csvWriter.writeRecords(userData);

    res.download(csvFilePath, `all-users-${Date.now()}.csv`, (err) => {
      if (err) console.error('Error downloading file:', err);
      fs.unlinkSync(csvFilePath);
    });

  } catch (error) {
    console.error('Error generating CSV:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to generate CSV' });
  }
});

// Download event-specific users as CSV
app.get('/download-event-users-csv/:eventId', authenticateToken, isAdminOrOrganizer, async (req, res) => {
  try {
    const { eventId } = req.params;

    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const registrationsCollection = db.collection("registrations");
    const usersCollection = db.collection("users");

    const event = await eventsCollection.findOne({ _id: new ObjectId(eventId) });
    if (!event) {
      return res.status(404).json({ status: 'Error', message: 'Event not found' });
    }

    const registrations = await registrationsCollection.find({ 
      eventId: new ObjectId(eventId) 
    }).toArray();

    if (registrations.length === 0) {
      return res.status(404).json({ status: 'Error', message: 'No registered users found' });
    }

    const userIds = registrations.map(r => r.userId);
    const users = await usersCollection.find({ 
      _id: { $in: userIds } 
    }).toArray();

    const csvFilePath = path.join(__dirname, `event-${eventId}-users-${Date.now()}.csv`);

    const csvWriter = createCsvWriter({
      path: csvFilePath,
      header: [
        { id: 'eventName', title: 'Event Name' },
        { id: 'eventDate', title: 'Event Date' },
        { id: 'fullName', title: 'Full Name' },
        { id: 'email', title: 'Email' },
        { id: 'rollNumber', title: 'Roll Number' },
        { id: 'branch', title: 'Branch' },
        { id: 'registeredAt', title: 'Registration Date' }
      ]
    });

    const registrationData = registrations.map(reg => {
      const user = users.find(u => u._id.toString() === reg.userId.toString());
      return {
        eventName: event.name,
        eventDate: event.date,
        fullName: user?.fullName || '',
        email: user?.email || '',
        rollNumber: user?.rollNumber || '',
        branch: user?.branch || '',
        registeredAt: reg.registeredAt ? new Date(reg.registeredAt).toLocaleDateString() : ''
      };
    });

    await csvWriter.writeRecords(registrationData);

    res.download(csvFilePath, `${event.name}-users-${Date.now()}.csv`, (err) => {
      if (err) console.error('Error downloading file:', err);
      fs.unlinkSync(csvFilePath);
    });

  } catch (error) {
    console.error('Error generating CSV:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to generate CSV' });
  }
});

// Download all events with stats as CSV
app.get('/download-events-csv', authenticateToken, isAdminOrOrganizer, async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const registrationsCollection = db.collection("registrations");

    const events = await eventsCollection.find({}).toArray();

    if (events.length === 0) {
      return res.status(404).json({ status: 'Error', message: 'No events found' });
    }

    const eventsWithCounts = await Promise.all(
      events.map(async (event) => {
        const registrationCount = await registrationsCollection.countDocuments({ 
          eventId: event._id 
        });
        return {
          id: event._id.toString(),
          name: event.name || '',
          date: event.date || '',
          venue: event.venue || '',
          strength: event.strength || 0,
          registrations: registrationCount,
          approved: event.approved ? 'Yes' : 'No',
          createdBy: event.createdBy?.fullName || '',
          createdAt: event.createdAt ? new Date(event.createdAt).toLocaleDateString() : ''
        };
      })
    );

    const csvFilePath = path.join(__dirname, `all-events-${Date.now()}.csv`);

    const csvWriter = createCsvWriter({
      path: csvFilePath,
      header: [
        { id: 'id', title: 'Event ID' },
        { id: 'name', title: 'Event Name' },
        { id: 'date', title: 'Date' },
        { id: 'venue', title: 'Venue' },
        { id: 'strength', title: 'Capacity' },
        { id: 'registrations', title: 'Registered Users' },
        { id: 'approved', title: 'Approved' },
        { id: 'createdBy', title: 'Created By' },
        { id: 'createdAt', title: 'Created At' }
      ]
    });

    await csvWriter.writeRecords(eventsWithCounts);

    res.download(csvFilePath, `all-events-${Date.now()}.csv`, (err) => {
      if (err) console.error('Error downloading file:', err);
      fs.unlinkSync(csvFilePath);
    });

  } catch (error) {
    console.error('Error generating CSV:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to generate CSV' });
  }
});

// ========================================
// SPONSOR IMAGE ROUTES
// ========================================
const multer = require('multer');

// Configure multer for sponsor images
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, 'public', 'sponsors');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'sponsor-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: function (req, file, cb) {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'));
    }
  }
});

// Serve static files (add this if not already present)
app.use('/sponsors', express.static(path.join(__dirname, 'public', 'sponsors')));

// Upload sponsor image
app.post('/sponsors/upload', authenticateToken, isAdminOrOrganizer, upload.single('sponsorImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ status: 'Error', message: 'No file uploaded' });
    }

    const db = client.db("project_event_db");
    const sponsorsCollection = db.collection("sponsors");

    const sponsor = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      path: req.file.path,
      url: `/sponsors/${req.file.filename}`,
      fullUrl: `${req.protocol}://${req.get('host')}/sponsors/${req.file.filename}`,
      uploadedBy: new ObjectId(req.user.userId),
      uploadedAt: new Date(),
      isActive: true,
      order: await sponsorsCollection.countDocuments()
    };

    const result = await sponsorsCollection.insertOne(sponsor);

    res.json({
      status: 'Success',
      message: 'Sponsor image uploaded successfully',
      sponsor: {
        id: result.insertedId,
        filename: sponsor.filename,
        url: sponsor.url,
        fullUrl: sponsor.fullUrl,
        uploadedAt: sponsor.uploadedAt
      }
    });

  } catch (error) {
    console.error('Error uploading sponsor image:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to upload image' });
  }
});

// Upload multiple sponsor images
app.post('/sponsors/upload-multiple', authenticateToken, isAdminOrOrganizer, upload.array('sponsorImages', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ status: 'Error', message: 'No files uploaded' });
    }

    const db = client.db("project_event_db");
    const sponsorsCollection = db.collection("sponsors");

    const currentCount = await sponsorsCollection.countDocuments();

    const sponsors = req.files.map((file, index) => ({
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      url: `/sponsors/${file.filename}`,
      uploadedBy: new ObjectId(req.user.userId),
      uploadedAt: new Date(),
      isActive: true,
      order: currentCount + index
    }));

    const result = await sponsorsCollection.insertMany(sponsors);

    res.json({
      status: 'Success',
      message: `${sponsors.length} sponsor images uploaded successfully`,
      sponsors: sponsors.map((s, i) => ({
        id: result.insertedIds[i],
        filename: s.filename,
        url: s.url,
        uploadedAt: s.uploadedAt
      }))
    });

  } catch (error) {
    console.error('Error uploading sponsor images:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to upload images' });
  }
});

// Get all sponsor images
app.get('/sponsors', async (req, res) => {
  try {
    const db = client.db("project_event_db");
    const sponsorsCollection = db.collection("sponsors");

    const sponsors = await sponsorsCollection
      .find({ isActive: true })
      .sort({ order: 1 })
      .toArray();

    // Add fullUrl for sponsors that don't have it
   const sponsorsWithUrls = sponsors.map(sponsor => {
      // Remove leading slash from url if it exists to prevent double slash
      const cleanUrl = sponsor.url?.startsWith('/') ? sponsor.url.substring(1) : sponsor.url;
      
      return {
        ...sponsor,
        url: cleanUrl || `sponsors/${sponsor.filename}`,
        fullUrl: sponsor.fullUrl || `${req.protocol}://${req.get('host')}/sponsors/${sponsor.filename}`
      };
    });

    res.json({
      status: 'Success',
      sponsors: sponsorsWithUrls
    });

  } catch (error) {
    console.error('Error fetching sponsors:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to fetch sponsors' });
  }
});

// Delete sponsor image
app.delete('/sponsors/:sponsorId', authenticateToken, isAdminOrOrganizer, async (req, res) => {
  try {
    const { sponsorId } = req.params;

    const db = client.db("project_event_db");
    const sponsorsCollection = db.collection("sponsors");

    const sponsor = await sponsorsCollection.findOne({ _id: new ObjectId(sponsorId) });
    if (!sponsor) {
      return res.status(404).json({ status: 'Error', message: 'Sponsor image not found' });
    }

    const filePath = path.join(__dirname, 'public', 'sponsors', sponsor.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await sponsorsCollection.deleteOne({ _id: new ObjectId(sponsorId) });

    res.json({
      status: 'Success',
      message: 'Sponsor image deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting sponsor image:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to delete sponsor image' });
  }
});

// Toggle sponsor active status
app.put('/sponsors/:sponsorId/toggle', authenticateToken, isAdminOrOrganizer, async (req, res) => {
  try {
    const { sponsorId } = req.params;

    const db = client.db("project_event_db");
    const sponsorsCollection = db.collection("sponsors");

    const sponsor = await sponsorsCollection.findOne({ _id: new ObjectId(sponsorId) });
    if (!sponsor) {
      return res.status(404).json({ status: 'Error', message: 'Sponsor image not found' });
    }

    const newStatus = !sponsor.isActive;
    await sponsorsCollection.updateOne(
      { _id: new ObjectId(sponsorId) },
      { $set: { isActive: newStatus } }
    );

    res.json({
      status: 'Success',
      message: `Sponsor image ${newStatus ? 'activated' : 'deactivated'} successfully`,
      isActive: newStatus
    });

  } catch (error) {
    console.error('Error toggling sponsor status:', error);
    res.status(500).json({ status: 'Error', message: 'Failed to toggle sponsor status' });
  }
});

// ========================================
// CALL THIS AFTER DATABASE INITIALIZATION
// Add this line inside initializeDatabase() function after line 153:
// setupAutomatedReminders();
// ========================================

// --------------------- FORGOT PASSWORD ENDPOINTS ---------------------

// Step 1: Send OTP to email
app.post('/forgot-password/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    console.log('📧 Forgot password: Send OTP requested for:', email);

    if (!email) {
      return res.status(400).json({
        status: 'Error',
        message: 'Email is required'
      });
    }

    const db = client.db('project_event_db');
    const usersCollection = db.collection('users');
    const otpCollection = db.collection('password_reset_otps');

    // Check if user exists
    const user = await usersCollection.findOne({ email });
    if (!user) {
      console.log('❌ User not found:', email);
      return res.status(404).json({
        status: 'Error',
        message: 'No account found with this email address'
      });
    }

    console.log('✅ User found:', user.fullName);

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('🔑 Generated OTP:', otp);

    // Store OTP in database (will auto-expire after 10 minutes)
    await otpCollection.updateOne(
      { email },
      {
        $set: {
          email,
          otp,
          createdAt: new Date(),
          verified: false
        }
      },
      { upsert: true }
    );

    // Send OTP via email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP - Event Management System',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center;">
            <h1 style="color: white; margin: 0;">Password Reset</h1>
          </div>
          
          <div style="background-color: #f7fafc; padding: 30px; border-radius: 10px; margin-top: 20px;">
            <p style="font-size: 16px; color: #2d3748;">Hello <strong>${user.fullName}</strong>,</p>
            
            <p style="font-size: 16px; color: #2d3748;">
              We received a request to reset your password. Use the OTP below to continue:
            </p>
            
            <div style="background-color: white; border: 2px dashed #667eea; border-radius: 10px; padding: 20px; text-align: center; margin: 30px 0;">
              <p style="font-size: 14px; color: #718096; margin-bottom: 10px;">Your OTP Code</p>
              <h2 style="font-size: 36px; color: #667eea; letter-spacing: 8px; margin: 0; font-weight: bold;">
                ${otp}
              </h2>
            </div>
            
            <p style="font-size: 14px; color: #e53e3e; margin-top: 20px;">
              ⏰ This OTP will expire in <strong>10 minutes</strong>
            </p>
            
            <p style="font-size: 14px; color: #718096; margin-top: 20px;">
              If you didn't request this, please ignore this email and your password will remain unchanged.
            </p>
          </div>
          
          <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
            <p style="font-size: 12px; color: #a0aec0;">
              Event Management System<br>
              This is an automated email, please do not reply.
            </p>
          </div>
        </div>
      `
    };

    const msg = {
  to: email,
  from: process.env.SENDGRID_FROM_EMAIL || process.env.EMAIL_USER || 'noreply@college.com',
  subject: 'Password Reset OTP - Event Management System',
  html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center;">
            <h1 style="color: white; margin: 0;">Password Reset</h1>
          </div>
          
          <div style="background-color: #f7fafc; padding: 30px; border-radius: 10px; margin-top: 20px;">
            <p style="font-size: 16px; color: #2d3748;">Hello <strong>${user.fullName}</strong>,</p>
            
            <p style="font-size: 16px; color: #2d3748;">
              We received a request to reset your password. Use the OTP below to continue:
            </p>
            
            <div style="background-color: white; border: 2px dashed #667eea; border-radius: 10px; padding: 20px; text-align: center; margin: 30px 0;">
              <p style="font-size: 14px; color: #718096; margin-bottom: 10px;">Your OTP Code</p>
              <h2 style="font-size: 36px; color: #667eea; letter-spacing: 8px; margin: 0; font-weight: bold;">
                ${otp}
              </h2>
            </div>
            
            <p style="font-size: 14px; color: #e53e3e; margin-top: 20px;">
              ⏰ This OTP will expire in <strong>10 minutes</strong>
            </p>
            
            <p style="font-size: 14px; color: #718096; margin-top: 20px;">
              If you didn't request this, please ignore this email and your password will remain unchanged.
            </p>
          </div>
          
          <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
            <p style="font-size: 12px; color: #a0aec0;">
              Event Management System<br>
              This is an automated email, please do not reply.
            </p>
          </div>
        </div>
      `
};
await sgMail.send(msg);

    console.log('✅ OTP email sent successfully');

    res.json({
      status: 'Success',
      message: 'OTP sent to your email address'
    });

  } catch (error) {
    console.error('❌ Error sending OTP:', error);
    res.status(500).json({
      status: 'Error',
      message: 'Failed to send OTP. Please try again.',
      details: error.message
    });
  }
});

// Step 2: Verify OTP
app.post('/forgot-password/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    console.log('🔑 Verify OTP requested for:', email);

    if (!email || !otp) {
      return res.status(400).json({
        status: 'Error',
        message: 'Email and OTP are required'
      });
    }

    const db = client.db('project_event_db');
    const otpCollection = db.collection('password_reset_otps');

    // Find OTP record
    const otpRecord = await otpCollection.findOne({ email });

    if (!otpRecord) {
      console.log('❌ No OTP found for email:', email);
      return res.status(404).json({
        status: 'Error',
        message: 'No OTP found. Please request a new one.'
      });
    }

    // Check if OTP is expired (10 minutes)
    const otpAge = Date.now() - new Date(otpRecord.createdAt).getTime();
    const tenMinutes = 10 * 60 * 1000;

    if (otpAge > tenMinutes) {
      console.log('❌ OTP expired for:', email);
      await otpCollection.deleteOne({ email });
      return res.status(400).json({
        status: 'Error',
        message: 'OTP expired. Please request a new one.'
      });
    }

    // Check if OTP matches
    if (otpRecord.otp !== otp) {
      console.log('❌ Invalid OTP for:', email);
      return res.status(400).json({
        status: 'Error',
        message: 'Invalid OTP. Please try again.'
      });
    }

    // Mark OTP as verified
    await otpCollection.updateOne(
      { email },
      { $set: { verified: true } }
    );

    console.log('✅ OTP verified successfully for:', email);

    res.json({
      status: 'Success',
      message: 'OTP verified successfully'
    });

  } catch (error) {
    console.error('❌ Error verifying OTP:', error);
    res.status(500).json({
      status: 'Error',
      message: 'Failed to verify OTP',
      details: error.message
    });
  }
});

// Step 3: Reset Password
app.post('/forgot-password/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    console.log('🔒 Reset password requested for:', email);

    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        status: 'Error',
        message: 'Email, OTP, and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        status: 'Error',
        message: 'Password must be at least 6 characters long'
      });
    }

    const db = client.db('project_event_db');
    const usersCollection = db.collection('users');
    const otpCollection = db.collection('password_reset_otps');

    // Verify OTP is verified
    const otpRecord = await otpCollection.findOne({ email });

    if (!otpRecord) {
      console.log('❌ No OTP record found');
      return res.status(404).json({
        status: 'Error',
        message: 'Invalid session. Please restart the process.'
      });
    }

    if (!otpRecord.verified) {
      console.log('❌ OTP not verified');
      return res.status(400).json({
        status: 'Error',
        message: 'Please verify OTP first'
      });
    }

    if (otpRecord.otp !== otp) {
      console.log('❌ OTP mismatch');
      return res.status(400).json({
        status: 'Error',
        message: 'Invalid OTP'
      });
    }

    // Update user password
    // Note: In production, you should hash the password with bcrypt
    const result = await usersCollection.updateOne(
      { email },
      { $set: { password: newPassword } }
    );

    if (result.matchedCount === 0) {
      console.log('❌ User not found:', email);
      return res.status(404).json({
        status: 'Error',
        message: 'User not found'
      });
    }

    // Delete OTP record
    await otpCollection.deleteOne({ email });

    console.log('✅ Password reset successful for:', email);

    // Send confirmation email
    const user = await usersCollection.findOne({ email });
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Successful - Event Management System',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; border-radius: 10px; text-align: center;">
            <h1 style="color: white; margin: 0;">✅ Password Reset Successful</h1>
          </div>
          
          <div style="background-color: #f7fafc; padding: 30px; border-radius: 10px; margin-top: 20px;">
            <p style="font-size: 16px; color: #2d3748;">Hello <strong>${user.fullName}</strong>,</p>
            
            <p style="font-size: 16px; color: #2d3748;">
              Your password has been successfully reset. You can now login with your new password.
            </p>
            
            <div style="background-color: #d1fae5; border-left: 4px solid #10b981; padding: 15px; margin: 20px 0;">
              <p style="font-size: 14px; color: #065f46; margin: 0;">
                🔒 If you didn't make this change, please contact support immediately.
              </p>
            </div>
          </div>
          
          <div style="text-align: center; margin-top: 30px;">
            <a href="https://centralized-academic-event-control.onrender.com/login" 
               style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                      color: white; 
                      padding: 15px 40px; 
                      text-decoration: none; 
                      border-radius: 10px; 
                      font-weight: bold;
                      display: inline-block;">
              Login Now
            </a>
          </div>
          
          <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
            <p style="font-size: 12px; color: #a0aec0;">
              Event Management System<br>
              This is an automated email, please do not reply.
            </p>
          </div>
        </div>
      `
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log('✅ Confirmation email sent');
    } catch (emailError) {
      console.error('⚠️ Failed to send confirmation email:', emailError);
      // Don't fail the request if email fails
    }

    res.json({
      status: 'Success',
      message: 'Password reset successful. Please login with your new password.'
    });

  } catch (error) {
    console.error('❌ Error resetting password:', error);
    res.status(500).json({
      status: 'Error',
      message: 'Failed to reset password',
      details: error.message
    });
  }
});