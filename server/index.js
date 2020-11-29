const express = require('express');
const app = express();
const path = require("path")
let cors = require('cors');

app.use(express.static(path.join(__dirname, 'public')))

app.use(express.json());
app.use(cors());

app.use( (req , res , next)  => {
    console.log(req.url + " " + (new Date().toTimeString()))
    next()
})

app.use('/api/users',require('./routes/users'))

// app.use('/api/exercices',require('./routes/exercices'))

app.listen(5000, () => { console.log("server open on port 5000") })