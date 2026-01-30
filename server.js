const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient, ServerApiVersion, ObjectId, Admin } = require("mongodb");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Razorpay = require('razorpay');
const crypto = require('crypto');
require("dotenv").config();


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



    await usersCollection.createIndex({ email: 1 }, { unique: true });


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


// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { fullName, rollNumber, branch, role, email, password } = req.body;
    if (!fullName || !rollNumber || !branch || !role || !email || !password) {
      return res
        .status(400)
        .json({ status: "Error", message: "All fields are required" });
    }


    const db = client.db("project_event_db");
    const usersCollection = db.collection("users");


    const existingUser = await usersCollection.findOne({ email });
    if (existingUser)
      return res
        .status(400)
        .json({ status: "Error", message: "Email already exists" });


    let approved = role === "user";


    const newUser = {
      fullName,
      rollNumber,
      branch,
      role,
      email,
      password: password,
      approved,
      createdAt: new Date(),
    };


    await usersCollection.insertOne(newUser);


    res
      .status(200)
      .json({
        status: "Success",
        message: `${role} registered successfully`,
      });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ status: "Error", message: "Registration failed" });
  }
});


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
app.get("/users", authenticateToken, isAdminOrOrganizer, async (req, res) => {
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
  isAdminOrOrganizer,
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
  isAdminOrOrganizer,
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
  isAdminOrOrganizer,
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
  isAdminOrOrganizer,
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
app.put("/events/:id", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const updatedData = req.body;


    const db = client.db("project_event_db");
    const eventsCollection = db.collection("events");
    const usersCollection = db.collection("users");
    const registrationsCollection = db.collection("registrations");


    const user = await usersCollection.findOne({ email: req.user.email });


    // Old event before update
    const oldEvent = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
    });
    if (!oldEvent) {
      return res.status(404).json({ message: "Event not found" });
    }


    const isAdmin = user.role === "admin";
    const isOrganizer = user.role === "organizer";


    // Admin edits stay approved, others go pending
    updatedData.approved = isAdmin ? true : false;
    updatedData.updatedAt = new Date();


    const result = await eventsCollection.updateOne(
      { _id: new ObjectId(eventId) },
      { $set: updatedData }
    );


    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Event not found" });
    }


    const successMessage = isAdmin
      ? "Event updated successfully"
      : "Event updated and submitted for re-approval";


    const newEvent = await eventsCollection.findOne({
      _id: new ObjectId(eventId),
    });


    // If non-admin updated, notify admins/organizers for review
    const userRole = user.role === "admin" || user?.role === "organizer" || user?.role === "user";


    if (!isAdmin) {
      const approvers = await usersCollection
        .find({ role: { $in: ["admin", "organizer"] } })
        .project({ _id: 1 })
        .toArray();


      const notifyPromises = approvers.map((u) =>
        createNotification({
          userId: u._id,
          eventId: newEvent._id,
          type: "event_updated_for_approval",
          title: "Event updated and needs review",
          message: `${user.fullName} updated the event "${newEvent.name}". Please review and approve.`,
        })
      );
      await Promise.all(notifyPromises);
    }


    // If admin/organizer changed date or venue, notify all registered users
    const dateChanged =
      oldEvent.date && newEvent.date && oldEvent.date !== newEvent.date;
    const venueChanged =
      oldEvent.venue && newEvent.venue && oldEvent.venue !== newEvent.venue;


    if ((dateChanged || venueChanged) && (isAdmin || isOrganizer)) {
      const regs = await registrationsCollection
        .find({ eventId: new ObjectId(eventId) })
        .toArray();


      const notifyUserPromises = regs.map((r) =>
        createNotification({
          userId: r.userId,
          eventId: newEvent._id,
          type: "event_updated",
          title: "Event details updated",
          message: `The event "${newEvent.name}" has updated details.\n\nNew date: ${newEvent.date}\nNew venue: ${newEvent.venue}`,
        })
      );
      await Promise.all(notifyUserPromises);
    }


    res.json({ message: successMessage });
  } catch (err) {
    console.error(err);
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
  isAdminOrOrganizer,
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
  isAdminOrOrganizer,
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
    const registrationsCollection = db.collection("registrations");
    const eventsCollection = db.collection("events");


    // Find registrations for this user
    const regs = await registrationsCollection
      .find({ userId: new ObjectId(requestedUserId) })
      .toArray();


    const eventIds = regs.map((r) => r.eventId);
    if (eventIds.length === 0) {
      return res.json({ status: "Success", events: [] });
    }


    // Fetch event details
    const allEvents = await eventsCollection
      .find({ _id: { $in: eventIds } })
      .toArray();


    const today = new Date();


    // Only events whose date is in the past are "attended"
    const attendedEvents = allEvents.filter((event) => {
      if (!event.date) return false;
      return new Date(event.date) < today;
    });


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
  isAdminOrOrganizer,
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