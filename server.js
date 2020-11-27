const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const Joi = require('joi');
const User = require('./user');

const app = express();

mongoose.connect('mongodb://localhost:27017', 
{ useNewUrlParser: true, useUnifiedTopology: true }, () => {
    console.log('Connected to database')
});

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

// Routes
// Login route
app.post('/login', (req, res) => {
    User.findOne({ username: req.body.username }, (err, user) => {
        if(err) throw err;
        if(!user) return res.status(422).json('username does not exist');

        bcrypt.compare(req.body.password, user.password, (err, result) => {
            if(err) throw err;
            if(result) {
                res.json(user);
            } else {
                res.status(422).json('wrong password');
            }
            
        });
    });
});

// Register route
app.post('/register', (req, res) => {
    const registerSchema = Joi.object({
        username: Joi.string().required().min(3),
        password: Joi.string().required().min(6),
        confirmPassword: Joi.string().required().min(6)
    });

    const { error } = registerSchema.validate(req.body);

    if(error) {
        res.status(422).json(error.details[0].message);
    } else {
        const { username, password, confirmPassword } = req.body;

        User.findOne({ username: username }, async (err, user) => {
            if(err) throw err;
            if(user) return res.status(422).json('username already exists');
            if(password !== confirmPassword) return res.status(422).json("passwords don't match");

            // waiting for bcrypt to finish before using hashedPassword
            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = new User({
                username: username,
                password: hashedPassword
            })
            // waiting for the new user to be saved before returnig a success message
            await newUser.save();
            res.status(200).json('registration successful')
        })
        
    }
    
});

app.get('/users', (req, res) => {
    User.find((err, users) => {
        if(err) throw err;
        res.json(users);
    });
});

app.get('/users/:search', (req, res) => {
    User.find({ username: req.params.search }, (err, users) => {
        if(err) throw err;
        if(users.length) {
            res.json(users) 
        } else {
            res.status(404).json('no match found')
        }
       
    });
});

app.delete('/', (req, res) => {
    User.deleteOne({ _id: req.body.id }, (err, result) => {
        if(err) throw err;
        res.json(result);
    });
});

app.listen(5000, () => console.log('Server started on port 5000'));


