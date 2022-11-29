const fs = require('fs');
const https = require('https');
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookiesSession = require('cookie-session');
const { verify } = require('crypto');
const port = 3000;
require('dotenv').config();

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};
const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log(profile);
  done(null, profile);
}
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));
//Save the session to the cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//Read the session from the cookie
passport.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

//middlewares
app.use(helmet());
app.use(
  cookiesSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_2, config.COOKIE_KEY_1],
  })
);
app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
  console.log('Current user is ', req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({ error: 'You must login!' });
  }
  next();
}

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  })
);
app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }),
  (req, res) => {
    console.log('Google called us back!');
  }
);
app.get('/secret', checkLoggedIn, (req, res) =>
  res.send('Your secret number is 19110420!')
);
app.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);
app.get('/auth/logout', (req, res) => {
  req.logOut();
  res.redirect('/');
});
app.get('/failure', (req, res) => res.send('Failed to login!'));

https
  .createServer(
    {
      key: fs.readFileSync(path.join(__dirname, 'key.pem')),
      cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
    },
    app
  )
  .listen(port, () => console.log(`Example app listening on port ${port}!`));
