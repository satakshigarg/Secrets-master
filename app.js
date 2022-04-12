//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

//Requiring packages required for authentication using passport
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

//Initialising the app
const app = express();
app.use(bodyParser.urlencoded({
    extended: true
}));
app.set("view engine", "ejs");
app.use(express.static("public"));

//Asking the app to use session
app.use(session({
    secret: "This is my secret that no one can know",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

//Connecting to mongoose database
mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

//Defining the user schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

//Adding the passport local mongoose plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Creating the model
const User = new mongoose.model("User", userSchema);

//Using static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

//Using static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

//Google oAuth2.0 strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//Defining routes

//Home route
app.get("/", function (req, res) {
    res.render("home");
});

//Login route
app.route("/login")
    .get(function (req, res) {
        res.render("login");
    })
    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function(err){
            if(err) {
                console.log(err);
            } else {
                console.log("No errors!");
                passport.authenticate("local")(req, res, function(){
                    console.log("Logged in");
                    res.redirect("/secrets");
                });
            }
        });
    });

//Google login path

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

//Register route
app.route("/register")
    .get(function (req, res) {
        res.render("register");
    })
    .post(function (req, res) {
        console.log(req.body.username);
        User.register({username: req.body.username}, req.body.password, function(err, user){
            if(err) {
                console.log(err);
            } else {
                console.log("Registered");
                passport.authenticate("local")(req, res, function(){
                    console.log("Logged in");
                    res.redirect("/secrets");
                });
            }
        });
    });

//Secrets route
app.route("/secrets")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            User.find({"secret" : {$ne: null}}, function(err, foundUsers) {
                if(err) {
                    console.log(err);
                } else {
                    if(foundUsers) {
                        res.render("secrets", {usersWithSecrets: foundUsers});
                    }
                }
            });
        } else {
            res.redirect("/login");
        }
    });

    app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect to secrets.
      res.redirect("/secrets");
    });

//Logout route
app.route("/logout")
    .get(function(req, res){
        req.logout();
        res.redirect("/");
    })

//Submit a new secret
app.route("/submit")
    .get(function(req, res){
        if(req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post(function(req, res){
        const newSecret = req.body.secret;
        const userId = req.user.id;
        User.findById(userId, function(err, foundUser){
            if(err) {
                console.log(err);
            } else {
                if(foundUser) {
                    foundUser.secret = newSecret;
                    foundUser.save(function(){
                        res.redirect("/secrets");
                    });
                }
            }
        });
    });

//Initialising the server
app.listen(3000, function () {
    console.log("Server is up and running on port 3000");
});