const express = require('express')
const session = require('express-session')
const flash = require('connect-flash')
const passport = require('passport')
const {Strategy: LocalStrategy} = require('passport-local')
const {connect} = require('mongoose')
const User = require('./models/User')
const {createHash,isValidPassword} = require('./utlis')
const cookieParser = require('cookie-parser')

const app = express()

connect('mongodb://localhost:27017/entrega13')
.then(_=> console.log('db connected'))
.catch(e=> console.log(e))
app.use(express.json())
app.use(express.urlencoded({extended: true}))
app.use(flash())
app.use(cookieParser())

app.use(session({
    secret: "qwerty",
    cookie: {maxAge: 600000},
    resave: true,
    saveUninitialized: true    
}))

app.use(passport.initialize())
app.use(passport.session())
app.set('view engine', 'ejs')

passport.use('login', new LocalStrategy((username, password, done)=>{
    return User.findOne({username})
    .then(user => {
        if(!user){
            return done(null, false, {message: 'usuario inexistente'})
        }

        if(!isValidPassword){
            return done(null, false, {message: 'contraseña incorrecta'})
        }
        return done(null, user)
    })
    .catch(err=> done(err))
}))

passport.use('signup', new LocalStrategy({
    passReqToCallback: true
},(req, username, password, done) => {
    return User.findOne({username})
    .then(user => {
        if(user){
            return done(null, false, {message: 'El username ya existe'})
        }

        const newUser = new User()
        newUser.username = username
        newUser.password = createHash(password)
        newUser.email = req.body.email

        return newUser.save()
    })
    .then(user => done(null, user))
    .catch(err => done(err))
}))

passport.serializeUser((user, done) => {
    done(null, user._id)
})

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user)
    })
})
    
app.get('/', (req, res, next) => {
    if(req.isAuthenticated()){
        return next()
    }

    return res.redirect('/login')
}, (req, res) => {
    return res.render('home', {username: req.user.username, email: req.user.email})
})

app.get('/login', (req, res)=>{
    return res.render('login', {message: req.flash('error')})
})

app.get('/signup', (req, res)=>{
    return res.render('signup', {message: req.flash('error')})
})

app.post('/login', passport.authenticate('login', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

app.post('/signup', passport.authenticate('signup', {
    successRedirect: '/login',
    failureRedirect: '/signup',
    failureFlash: true
}) )

app.post('/logout', (req, res)=>{
    if (!req.isAuthenticated()){
        return res.redirect('/login')
    }

    return req.session.destroy(err=>{
        if(!err){
            return res.redirect('/login')
        }
        return res.send('error')
    })
})

const PORT = 8080

app.listen(PORT, ()=>{
    console.log('app running on port 8080')
})
