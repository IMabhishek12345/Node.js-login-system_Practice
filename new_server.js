if (process.env.NODE_ENV!=="production"){
    require("dotenv").config()
}


const express=require("express");
const app=express();
const passport=require("passport");
const bcrypt=require("bcrypt");
const localStrategy=require("passport-local").Strategy;
const session=require("express-session");
const flash=require("express-flash");
const methodOverride=require("method-override");
const users=[];

const initializePassport=(passport,getUserbyEmail,getUserbyId)=>{
    
    const authenticateUser= async (email,password,done)=>{
        const user= await getUserbyEmail(email);
        if (user==null){
            return done(null,false,{message: "No user with this mail exists"})
        }
       
        try{
        
            if ( await bcrypt.compare(password,user.password)){
            return done(null,user);  
            }else{
            return done(null,false,{message: "password incorrect"})
            }
         }
        catch(err){
           return done(err);
           }   
        }
     passport.use(new localStrategy({usernameField:"email" },authenticateUser))           
     passport.serializeUser((user,done)=> done(null,user.id));
     passport.deserializeUser((id,done)=>done(null,getUserbyId(id)));
    }

initializePassport(passport,email=> users.find(user=>user.email===email),
    id => users.find(user=>user.id===id))

app.set("view-engine","ejs");

app.use(express.urlencoded({extended:false}));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(methodOverride("_method"));

const checkAuthenticated=(req,res,next)=>{
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect("/login")
}
const checknotAuthenticated=(req,res,next)=>{
    if (req.isAuthenticated()){
        return res.redirect("/");
    }
    next();
}
//this delete is not supoorted by our form that's why 
//we use method-override of node using that we can surpass
// POST by DELETE

app.delete("/logout",(req,res,next)=>{
    req.logOut((err)=>{
        if (err) return next(err)
    res.redirect("/");    
    })
})

app.get("/",checkAuthenticated,(req,res)=>{
    res.render("index.ejs",{name:req.user.name})
})
app.get("/register",checknotAuthenticated,(req,res)=>{
    res.render("register.ejs")
})

app.get("/login",checknotAuthenticated,(req,res)=>{
    res.render("login.ejs")
})
app.post("/login", checknotAuthenticated,passport.authenticate("local",{
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash:true
}))

app.post("/register",checknotAuthenticated,async(req,res)=>{

    try {
        const hashedPassword= await bcrypt.hash(req.body.password,10);
        users.push({
         id: Date.now().toString(),
         name: req.body.name,
         email: req.body.email,
         password: hashedPassword  
        })
        res.redirect("/login");
    } catch {
        res.redirect("/register");
    }
})


app.listen(3000);