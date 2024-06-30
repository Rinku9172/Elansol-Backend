const express = require('express');
const router = express.Router();
const User = require("../models/User");
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var fetchuser = require('../middleware/fetchuser');
const JWT_SECRET =process.env.JWT_SECRET;

//Route1:create a user using:POST “/api/auth/createuser.No login required
router.post('/createuser', [
    body('name', "Enter a valid name").isLength({ min: 3 }),
    body('email', "Enter a valid email").isEmail(),
    body('password', "Password must be at least 5 characters").isLength({ min: 5 }),
    body('date', "Enter a valid date").isISO8601()
], async (req, res) => {
    let success = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success, errors: errors.array() });
    }

    try {
        // Check if user already exists
        let user = await User.findOne({ email: req.body.email });
        if (user) {
            return res.status(400).json({ success, error: "A user with this email already exists" });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        // Create a new user
        user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            date: req.body.date
        });

        await user.save();

        // Generate JWT token
        const data = {
            user: {
                id: user.id
            }
        };
        const authToken = jwt.sign(data, JWT_SECRET);

        success = true;
        res.json({ success, authToken , user: {
            name: req.body.name,
            email: req.body.email,
            date:req.body.date
          },});

    } catch (error) {
        console.error(error.message);
        res.status(500).send("Server Error");
    }
});

//Route2:Authentictae a user using:POST “/api/auth/login". No login required
router.post('/login', [
    body('name', "Enter a valid name").isLength({ min: 3 }),
    body('password', "Password cannot be blank").exists(),
], async (req, res) => {
    let success = false;
    // If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name, password } = req.body;
    try {
        let user = await User.findOne({ name });
        if (!user) {
            success = false;
            return res.status(400).json({ error: "Please try to login with correct credentials" })
        }
        let passwordCompare = await bcrypt.compare(password, user.password);
        if (!passwordCompare) {
            success = false;
            return res.status(400).json({ success, error: "Please try to login with correct credentials" })
        }
        const data = {
            user: {
                id: user.id
            }
        }
        const authToken = jwt.sign(data, JWT_SECRET);
        success = true;
        res.json({ success, authToken,user: {
            id: user.id,
            name: user.name,
            email: user.email,
            date:user.date
          }, })
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
})

//Route1:Get loggedin user details using:POST “/api/auth/getuser".Login required
router.post('/getuser', fetchuser, async (req, res) => {
    try {
        userId = req.user.id;
        const user = await User.findById(userId).select("-password");
        res.send(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server error");
    }
})
module.exports = router;