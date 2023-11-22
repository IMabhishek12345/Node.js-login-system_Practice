const express=require("express");
const app=express();

app.set("view-engine","ejs");

app.use(express.urlencoded({extended:false}));

app.get("/",(req,res)=>{
    res.render("index.ejs",{name:"Abhishek"})
})
app.get("/register",(req,res)=>{
    res.render("register.ejs")
})


app.listen(3000);