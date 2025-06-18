const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// User Signup
router.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Check if user exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }
        
        // Create new user
        user = new User({ name, email, password });
        await user.save();
        
        // Create token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );
        
        res.status(201).json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// User Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Create token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );
        
        res.json({ 
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                walletAddress: user.walletAddress,
                balance: user.balance,
                level: user.level
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

module.exports = router;
