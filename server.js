'use strict';
// Internal modules - built-in
const path = require('path');

// External modules
require('dotenv').config({ path: path.join(__dirname, 'sample.env') });
const express = require('express');
const myDB = require('./connection');
const fccTesting = require('./freeCodeCamp/fcctesting.js');
const morgan = require('morgan');
const passport = require('passport');
const session = require('express-session');
const passportSocketIO = require('passport.socketio');
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo')(session);
const URI = process.env.MONGO_URI;
const store = new MongoStore({ url: URI });

// Internal modules
const routes = require('./routes');
const auth = require('./auth');

const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.set('view engine', 'pug');
app.use(session({
    key: 'express.sid', 
    secret: process.env.SESSION_SECRET,
    store: store,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false },
}));
app.use(passport.initialize());
app.use(passport.session());

myDB(async client => {
    const myDataBase = await client.db('database').collection('users');
    auth(app, myDataBase);
    routes(app, myDataBase);

    // IO
    let currentUsers = 0;
    io.use(
        passportSocketIO.authorize({
            cookieParser: cookieParser,
            key: 'express.sid',
            secret: process.env.SESSION_SECRET,
            store: store,
            success: onAuthorizeSuccess,
            fail: onAuthorizeFail,
        })
    )
    io.on('connection', socket => {
        ++currentUsers;
        const name = socket.request.user.name;
        io.emit('user', {
            name,
            currentUsers,
            connected: true,
        });
        console.log(`user ${name} connected!`);

        socket.on('chat message', message => {
            io.emit('chat message', {
                name,
                message,
            });
        });

        socket.on('disconnect', socket => {
            --currentUsers;
            io.emit('user', {
                name,
                currentUsers,
                connected: false,
            });
            console.log(`user ${name} disconnected!`);;
        });
    });

    // IO callbacks
    function onAuthorizeSuccess(data, accept) {
        console.log('successful connection to socket.io');
        accept(null, true);
    }

    function onAuthorizeFail(data, message, error, accept) {
        if(error) throw new Error(message);
        console.log('failed connection to socket.io', message);
        accept(null, false);
    }
    
}).catch(e => {
    app.route('/').get((req, res) => {
        res.render('pug', { title: e, message: 'Unable to login' });
    });
});

http.listen(process.env.PORT || 3000, () => {
  console.log('Listening on port ' + process.env.PORT);
});