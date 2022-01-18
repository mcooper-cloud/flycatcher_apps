// hello world
const https = require('https')
const fs = require('fs')
const express = require('express')
const path = require('path');
const app = express()

app.get('/', (req, res) => {
    res.send('Hello world from a Node.js app!')
})


if (process.env.LOADBALANCER_PORT == 443){

    https.createServer({
        key: fs.readFileSync(path.resolve('./cert/dev.key')),
        cert: fs.readFileSync(path.resolve('./cert/dev.crt'))
    }, app).listen(3000, () => {
        console.log('Listening...')
    })


} else {

    app.listen(3000, () => {
        console.log('Server is up on 3000')
    })

}

