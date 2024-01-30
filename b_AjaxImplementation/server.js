const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

//Parse incoming requests

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname));


app.get('/output', (req, res) => {
    res.send('This is the output page');
});

//POST request
app.post('/output', (req, res) => {
    const { name, email, username, password } = req.body;
    const response = `Name: ${name}, Email: ${email}, Username: ${username}, Password: ${password}`;
    res.send(response);
});


app.listen(port, () => {
    console.log('Server is running ');
})